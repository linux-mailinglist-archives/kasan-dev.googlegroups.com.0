Return-Path: <kasan-dev+bncBCS4VDMYRUNBBRGLSW4QMGQEQO7RIGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id C58F69B9B31
	for <lists+kasan-dev@lfdr.de>; Sat,  2 Nov 2024 00:35:34 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2e2c6a5fc86sf2443356a91.2
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Nov 2024 16:35:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730504133; cv=pass;
        d=google.com; s=arc-20240605;
        b=JIDJSCOHXvep4j6GqFAeulyia2TpwmLeCsB0FuI6/tEFJHu4NPAdfiCviC6e6j5tOk
         oS7Hdpq676vyeahUzYAjQIELs5LzDskIRd9RMQyNiVYAQPanJXjqg3Z7JTdaBlOyy5oZ
         +UFC916DduOqhU+fa9vmWmvPyZVX9YvnJY53krCKqwAUVlW1yW7pbREaQgUK089+KyQI
         ic6TnSuBpZx3O2z+rgsRguSX/PSKPHZcwQLt4HOP9ZJ23a/8ePt7sDY2TcrKj3NqYuGq
         +HxWNVSfSWl7JtiYDaFwnRZNUZovAgM9hrL/P0zbd4VeJ5Smi8RlkyG/8CcjV53Pprw7
         za3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=r6dcSiqae71aZaqDyk7QqTnUrtKM8cju7Fl4NQ2uFB0=;
        fh=9jO7+N5fTC+KgwEh6XUhgcpYIYvdATVrsp+edNcQjMY=;
        b=f+o0floMkzefQXr/bHXBXNpa0URffANGxHWmpOORgsoO2C3sjLXX+742kKMPSoLL+e
         BvHd1FE9oofa+Z3rNi3KRoF3by16grBkuqxsGwl46SpqrWZg5C6zngdKaZ65AuhC1gOe
         dY4DqpxfpnKyl9uMgobHlbxFSWCJLl+lbtCOTDEUTXrUTOUCQGSoAkmyAJI8VJ8EfT9n
         FZMGXsB21jkIpt5c1uqrnc2Iq7cHpyxPSx8n2aex9vTCD6CwzNkTnfj59RV6omUpCtX6
         iuqXIBgrfYVUGZ8G811bUg1UzW8Ynnbj9Xj35Sd8Ue0n/uTUf+p4Py7YOxRVpQ7CDk/f
         lKPA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UixwKEY5;
       spf=pass (google.com: domain of srs0=xeo+=r4=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=Xeo+=R4=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730504133; x=1731108933; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=r6dcSiqae71aZaqDyk7QqTnUrtKM8cju7Fl4NQ2uFB0=;
        b=HLyh4Y70UwNTHz1LDUr+ii2MJyWemHSuuo0bkscMhAu/dvdCrvDLWKi25VLzMztJUC
         JCcSVFn/EmQhlkLEbGmsEpITxEiqcp9vgyD0ATU5O8ZEH+MGQn39eAP7mK/CB12x6FTz
         n2i7mhT2eQsdTKWbaY4F6Y9dpzkIKVrYb17jJBc546ygTXyZVFQFcWf9ohq4adv4LnoI
         hqvNt0LVhaLKWMzTIIRP0HIrc3Azl2lIgc+FkJOEkEuur7G9pBksLp6v/7KRkpCsPY2R
         pkcyFvCCrFBeQszjicRBlH9teDujVBQ4urbHbEO0758sFagZCiy0tGyFnyHSWgQuWKro
         PlUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730504133; x=1731108933;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=r6dcSiqae71aZaqDyk7QqTnUrtKM8cju7Fl4NQ2uFB0=;
        b=AJitJMNkHuXRWtNGtRBnRm3OlBDiu3uxl8oa0JYumhCIfysqFKoqzE77v1RTVWS7rz
         5a35AkP9xCqQyAQjlgyGvMTyyhcMebVQRte82dFmynRFoGtHVisheHXyCYK95URj8her
         6IKpEEBwcP3EH3R57j3h+iUV/W56G5JATKwFj25Ujf0YVFsYbeD+MJAgIv4M5acs9+zU
         CN0asRWJ+ettMcXawmSZ+3h3OsZIgZf0hXVYobZ/JVCtYMTHgGCPyXQswNrQ1hVrdjQv
         NOa1BlUqBgYOxjbsDAL49W32mAq68dgLCK4PlhMhMkFAMvgSmZIhBm8tUnLEu6rf959b
         7t4Q==
X-Forwarded-Encrypted: i=2; AJvYcCXIfbk6dUmeFgFbGX4tMT69pkkhS7k2tNKLbA3yf1vQ5n6K1zC7nig5/Is9J4xQI4rKdjBeWg==@lfdr.de
X-Gm-Message-State: AOJu0YzZ0K6xKP3tVm6mn0vr33HbKlrKXN2jfscQNM4Du5KMNRfO6COE
	J0EXOazIXOZkWlL6wHKWpgtlNQwjcnVijBvsMHZcNP5i2DtHCxue
X-Google-Smtp-Source: AGHT+IEFNnj5niZ9BfmHMpkFBTMY+nhdWUpAza8qCeA8Li7fe3DWZtKy3Tt4aF/WM9J4ls6Tr0kQaA==
X-Received: by 2002:a17:90b:4c8d:b0:2e2:af53:9326 with SMTP id 98e67ed59e1d1-2e8f11b895dmr29977039a91.30.1730504132441;
        Fri, 01 Nov 2024 16:35:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c596:b0:2e2:c774:2b42 with SMTP id
 98e67ed59e1d1-2e93abb7764ls1896061a91.0.-pod-prod-09-us; Fri, 01 Nov 2024
 16:35:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUzT9phBR3UsZiGuzpEf3tsxt1wC7ykzGpfS5DvvpYOD46lVMduk092MsdvhigtMi9ZkdyyiXTvSCM=@googlegroups.com
X-Received: by 2002:a17:90a:ca83:b0:2e2:ad29:11a4 with SMTP id 98e67ed59e1d1-2e8f11b894fmr25934411a91.25.1730504131104;
        Fri, 01 Nov 2024 16:35:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730504131; cv=none;
        d=google.com; s=arc-20240605;
        b=Rj8OUFVkEgk0ijes6nNntfRdwFABL347zMvU0c5lgPDDlPSRlhU1eH3MgWKWWD3wr+
         6yMUhDDEZBRqGUqIveJlzYRxAFI4U3UO55npauzIC+dF+pl1H5ZW4D1oNGR/IEE0qZ4z
         oRuqhLM0hjn7mG2NxmLZTh966tlQasfn9/CGEP3YHzmbWvFkAJb9ZmGQayt+Jlx9tOvA
         LhweIrMiHyK8/3errIqsxG70MmlYzRdObcPzvYOv14PgGB/awMQ/c1w5bAMtSCbHad4K
         eNgj3l2HMk8EV4GbG0qisigYg8RY61uQnXlf9O9ZDwFdhesi3Ywa14Msk22IxlPsKz3x
         aNvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=SCbdCxoBNvMNL36FTFydtOQ3LLCEfsyrMJMfCrZBvyc=;
        fh=sgMI7tmNu/xPld+3m5xVJvRQdKiIcc7Lsrt9++K6A78=;
        b=C6CmnvW1ZoscWCy7bkPCrQGITOJ3j3EKfP8cqY7hV3uM9YtuI0XrQOKBD/wN2C4BPr
         wQ1I1Fs1HIpeSSIZU/Cqh31uMTJtkg3i7ri32W4SL0T1KKVW9vdr/Cf+nrzBiu0JaAsB
         Q4B9j8n3vG0KQQPjk0tDiShdtCe9bLHYjG+8zTKkScOzF0s+5Y/dHm4P58zeh9z+ZzrS
         OXnr2oxsfHsvyJFRRti3yXfRvcQ2bn8aqRwHGsRh0Bsvk3hQY/N2e4y0+Qe9KcV6Kpil
         ZStqy/4wxZZs1xqcKSrgSGhoRxPjh4+W8oLEq/RnMQOyBDtLh7GAR3bDLfOS1Ft/HDxG
         k+dQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UixwKEY5;
       spf=pass (google.com: domain of srs0=xeo+=r4=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=Xeo+=R4=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e9201b9b95si458527a91.0.2024.11.01.16.35.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Nov 2024 16:35:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xeo+=r4=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 81093A446E3;
	Fri,  1 Nov 2024 23:33:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3EB10C4CECD;
	Fri,  1 Nov 2024 23:35:29 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id D3782CE0F74; Fri,  1 Nov 2024 16:35:28 -0700 (PDT)
Date: Fri, 1 Nov 2024 16:35:28 -0700
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Boqun Feng <boqun.feng@gmail.com>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, Marco Elver <elver@google.com>,
	linux-next@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	sfr@canb.auug.org.au, longman@redhat.com, cl@linux.com,
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
	akpm@linux-foundation.org, Thomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>
Subject: Re: [PATCH] scftorture: Use workqueue to free scf_check
Message-ID: <37c2ad76-37d1-44da-9532-65d67e849bba@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <ZyUxBr5Umbc9odcH@boqun-archlinux>
 <20241101195438.1658633-1-boqun.feng@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241101195438.1658633-1-boqun.feng@gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=UixwKEY5;       spf=pass
 (google.com: domain of srs0=xeo+=r4=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=Xeo+=R4=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

On Fri, Nov 01, 2024 at 12:54:38PM -0700, Boqun Feng wrote:
> Paul reported an invalid wait context issue in scftorture catched by
> lockdep, and the cause of the issue is because scf_handler() may call
> kfree() to free the struct scf_check:
> 
> 	static void scf_handler(void *scfc_in)
>         {
>         [...]
>                 } else {
>                         kfree(scfcp);
>                 }
>         }
> 
> (call chain anlysis from Marco Elver)
> 
> This is problematic because smp_call_function() uses non-threaded
> interrupt and kfree() may acquire a local_lock which is a sleepable lock
> on RT.
> 
> The general rule is: do not alloc or free memory in non-threaded
> interrupt conntexts.
> 
> A quick fix is to use workqueue to defer the kfree(). However, this is
> OK only because scftorture is test code. In general the users of
> interrupts should avoid giving interrupt handlers the ownership of
> objects, that is, users should handle the lifetime of objects outside
> and interrupt handlers should only hold references to objects.
> 
> Reported-by: "Paul E. McKenney" <paulmck@kernel.org>
> Link: https://lore.kernel.org/lkml/41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop/
> Signed-off-by: Boqun Feng <boqun.feng@gmail.com>

Thank you!

I was worried that putting each kfree() into a separate workqueue handler
would result in freeing not keeping up with allocation for asynchronous
testing (for example, scftorture.weight_single=1), but it seems to be
doing fine in early testing.

So I have queued this in my -rcu tree for review and further testing.

							Thanx, Paul

> ---
>  kernel/scftorture.c | 14 +++++++++++++-
>  1 file changed, 13 insertions(+), 1 deletion(-)
> 
> diff --git a/kernel/scftorture.c b/kernel/scftorture.c
> index 44e83a646264..ab6dcc7c0116 100644
> --- a/kernel/scftorture.c
> +++ b/kernel/scftorture.c
> @@ -127,6 +127,7 @@ static unsigned long scf_sel_totweight;
>  
>  // Communicate between caller and handler.
>  struct scf_check {
> +	struct work_struct work;
>  	bool scfc_in;
>  	bool scfc_out;
>  	int scfc_cpu; // -1 for not _single().
> @@ -252,6 +253,13 @@ static struct scf_selector *scf_sel_rand(struct torture_random_state *trsp)
>  	return &scf_sel_array[0];
>  }
>  
> +static void kfree_scf_check_work(struct work_struct *w)
> +{
> +	struct scf_check *scfcp = container_of(w, struct scf_check, work);
> +
> +	kfree(scfcp);
> +}
> +
>  // Update statistics and occasionally burn up mass quantities of CPU time,
>  // if told to do so via scftorture.longwait.  Otherwise, occasionally burn
>  // a little bit.
> @@ -296,7 +304,10 @@ static void scf_handler(void *scfc_in)
>  		if (scfcp->scfc_rpc)
>  			complete(&scfcp->scfc_completion);
>  	} else {
> -		kfree(scfcp);
> +		// Cannot call kfree() directly, pass it to workqueue. It's OK
> +		// only because this is test code, avoid this in real world
> +		// usage.
> +		queue_work(system_wq, &scfcp->work);
>  	}
>  }
>  
> @@ -335,6 +346,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
>  			scfcp->scfc_wait = scfsp->scfs_wait;
>  			scfcp->scfc_out = false;
>  			scfcp->scfc_rpc = false;
> +			INIT_WORK(&scfcp->work, kfree_scf_check_work);
>  		}
>  	}
>  	switch (scfsp->scfs_prim) {
> -- 
> 2.45.2
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/37c2ad76-37d1-44da-9532-65d67e849bba%40paulmck-laptop.
