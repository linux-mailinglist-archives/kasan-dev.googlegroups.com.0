Return-Path: <kasan-dev+bncBCS4VDMYRUNBBK475S7AMGQEE4NCNOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id E28A9A69836
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 19:40:45 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-2feb47c6757sf5379533a91.3
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 11:40:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742409644; cv=pass;
        d=google.com; s=arc-20240605;
        b=b3mm90QxmNkuUY2leiJarllLA148Mvss3kszrW8rzle5V1QqHmAgQOy4eL50yzOoiW
         huJvyT1vm0zIsB1Z8rpnY3f/2yzTMKF8aqSP2lBVLEfFkq8a/8XVNwFEaadhfIT4IgKF
         RVuGc2AfIBrvY0tPJpFVV01QZCmSrX+Gj57h5jQ/UnlaCwvmxM58/sgMwH7isz56/qes
         UXt97PeA/CgZl1oVmmpAfHPaCD+ulDQ9NTRKrBOBenbsglFfaWcpJlZUIEVa9pvhCJof
         90H/Dg96zCAPzeuQi0LyxxQxXvzLJ3EcPfPSesELwL0/DiTYaTB5mW6E8fmLy/3fbEtz
         HSbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=2WXt6xu3mfBm7D87sVoq80lvJhHDpZ7YxPfa2BYWO5o=;
        fh=+iF2tqwFvVoMvMd6PPQn0imiG/jOk0m3xffmjQlAmh8=;
        b=j32Re1WGxew1vDks+GDJNPlS5ASbkU7Q2VKzgzR6SW9EMYZJAuNPjvm858sNXUbbvi
         Wl1yGBuqjcsT3NNVEHwSF6+6JWNjQ6SAoMc2E2ejtNOYq/Fa9jWje1NPSqT4yMWL/7QO
         s2J6wBUwRv7QFnoNIWe0SPyfqPsIpAXlEmIF3EvF9VFmPyPXkoG7VCB7/HnmhbZu9UxA
         QGBNDc35p9EQubvoPUkgVt1cBJt8N/z635pOSjBDxPdIWIs0CGI0WEpqdDeHWZcRvG4V
         +P8TMwxA/Kh5j32tgOyVk8dTg+BlGRa+2ZW4G3dGIhKJzPRz62MvEwn7hmooEVhZxtJN
         XeMg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QQSldM6p;
       spf=pass (google.com: domain of srs0=en1s=wg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom="SRS0=eN1s=WG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742409644; x=1743014444; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2WXt6xu3mfBm7D87sVoq80lvJhHDpZ7YxPfa2BYWO5o=;
        b=WKx1PmuYuFRYb2obCFd3y95bwu+R29xJlRO6xWXTdJswu+zn86Gg93T2ZUeqbZiXoS
         n63W1KMoyBim3ReaBKaj2dqqAcyFUXXT9A3uoX5WW1GzpI39jJyD+hQ2BilVgjOnLQIQ
         ZOvAl+2lYHwP8X2kbZ1StPgTqmG5j9jLB0sjkHGxvpqDgzh1XjeQXebiYAP/oGWtSWXj
         YqLVHBoTcFyRyBRHcz1fpjgN3EyYXfHCymwTYvXLwZeL/d7t8TRI/8b42eDuY/Ef6rxl
         WmSBb8NpeWQ1evCD5HNf3Lo4qxkVJCh57HS15PpV8E8wGebT/pid7a7TYjisXAB97Ctk
         EXrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742409644; x=1743014444;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2WXt6xu3mfBm7D87sVoq80lvJhHDpZ7YxPfa2BYWO5o=;
        b=GvGAadZMZ7nWwykAhTYUj30QgRWlCRu8cH++WRBqRbiymeJrSRSDAZbYwt0t3oLO+/
         B51awedeAXzND2rq/fIxqJUfDloA/3GddzDHWPhk7/iNjWNCtHHmA96DwLxZTuShJ3+S
         GhHwMG18lZXY9TjRc34wJ8XDIHqNMbTkICsunYpBlzbqCSIi5MWfssRrtqVmBsE0WJAm
         LxGMK69XGEnRvlY6LTLfhQyu243D8+PbfFGr8pksjF1IyJ87p52tahp2l5ZCEr9xxfcL
         +y9jIf1J7QxywbHCfuDBP9ym01VGIZ78Ngp9pUIRdiPNNWJ7LjCDanIOqNnrRMz5QNpc
         A94Q==
X-Forwarded-Encrypted: i=2; AJvYcCU8JQfQ3xgzOHXl2EIrsvEVFR57rujzCPEdlFY7uMCoyrUaYTpkhPznps/DRGBdQB8lsJEQGg==@lfdr.de
X-Gm-Message-State: AOJu0YzDyUMWXBy5UZFm1dVThxAl3WGKHTQHHq3qSPuULxshIBsdtA+O
	PP2Q4zZLkG5FaQjZJ7jFb5hdf2ymJq/oD41xlLFWwTfOklvtQbu9
X-Google-Smtp-Source: AGHT+IGn9VKfrbaMyVEqVvk7ut817B5KxtIrpiN4jdIKSrZasvCutNEvmSTsHkL0D/uroqsHbvOZxw==
X-Received: by 2002:a17:90b:5343:b0:2ff:4bac:6fa2 with SMTP id 98e67ed59e1d1-301bde739d7mr6558151a91.16.1742409644228;
        Wed, 19 Mar 2025 11:40:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJcqix4j+6pxoJSJs/PxVkw+ZoHY/ld1HhN3f+5CPQP8w==
Received: by 2002:a17:90a:6d02:b0:2fa:5303:b1e3 with SMTP id
 98e67ed59e1d1-301d41bbfb0ls118744a91.1.-pod-prod-01-us; Wed, 19 Mar 2025
 11:40:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW4ztyXL9xNfkTbxs7aSk4o4gLL46vN7F3udqPlGOKbIqtMFwSrCSIuCzIptoWGdMK+9kV6rYmXC3E=@googlegroups.com
X-Received: by 2002:a17:903:1ce:b0:221:78a1:27fb with SMTP id d9443c01a7336-2264981b453mr51729115ad.11.1742409642704;
        Wed, 19 Mar 2025 11:40:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742409642; cv=none;
        d=google.com; s=arc-20240605;
        b=GONowOfMAcfdgdX9tvKkjARIU1oj97zqRh8zJraRh+Yhgi1a2wH4RC3VzXv4x7Eynb
         zM720JpNdgy3kC4K2WeFFYwyDL+iYWtqK2anPyLO8LR7QjWSDIB3EobQKIHlXYdpq6Eb
         03uRlhmS8qZ/NuZuXnSHC/JMd5ZeFaaxn9sjS60KqbC6FBIK+RovdEWW1lulXrhTtWCV
         83xulGTmYQ80mKhMb5gx3aGpmFuPGih6dHgCpk5B6K50i6w+59dXRH4qnvzhS5XUkDX7
         a/V9I2/9EOh5A9jQ4M6pkFJVI+b6qdM0KRtLMyd1FRLNYZrvjUserNtS1sVG2yPQRYm6
         jBqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Avnzpo3Mo5um+QoDIkoELl0KTCA+0Igcoks59Kr7Dhs=;
        fh=DaCab4aqHAA8zZ7L0umtNXbC/JT48dSeqYRXnqXnXek=;
        b=XTVIVV/Wa1nve2qopENDQ2G4UEcCHErRT480mhE/C+fJbWGspZP3xhUjJEX2MDun4L
         fumozDj87TX5jtpi1MkwSl9wnQhuvoChDnPJMzXx5I4WDGkVYPwrJ4FeTV2agvnDR71l
         +HJPdFSZHQ103aytku3nBW+ckPHbwY31ok8yngYDX0p0131kzl8y5E2GZe/69b7ZlhCZ
         Z683/soVCAxhvHcM3iOXti4ZPlLs2szrr8UapaAoVRcemh42VwfF8CyZe3DYhYJv7BL0
         O4IW22GiSGqJr8e8d6vVGyQ2FlLtfBqRzoJaSXohatswGln8l9LXyeMkiiiUP6Jc9iKT
         kTQw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QQSldM6p;
       spf=pass (google.com: domain of srs0=en1s=wg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom="SRS0=eN1s=WG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-225c6c00e40si5269425ad.7.2025.03.19.11.40.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Mar 2025 11:40:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=en1s=wg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 1453F6814E;
	Wed, 19 Mar 2025 18:40:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 24BB7C4CEE4;
	Wed, 19 Mar 2025 18:40:41 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id BC687CE0BC5; Wed, 19 Mar 2025 11:40:40 -0700 (PDT)
Date: Wed, 19 Mar 2025 11:40:40 -0700
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Breno Leitao <leitao@debian.org>
Cc: longman@redhat.com, bvanassche@acm.org,
	Eric Dumazet <edumazet@google.com>, kuba@kernel.org,
	jhs@mojatatu.com, xiyou.wangcong@gmail.com, jiri@resnulli.us,
	kuniyu@amazon.com, rcu@vger.kernel.org, kasan-dev@googlegroups.com,
	netdev@vger.kernel.org
Subject: Re: tc: network egress frozen during qdisc update with debug kernel
Message-ID: <89ca1978-de9e-4502-8a3b-970ad8fd9fcf@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20250319-meticulous-succinct-mule-ddabc5@leitao>
 <CANn89iLRePLUiBe7LKYTUsnVAOs832Hk9oM8Fb_wnJubhAZnYA@mail.gmail.com>
 <20250319-sloppy-active-bonobo-f49d8e@leitao>
 <5e0527e8-c92e-4dfb-8dc7-afe909fb2f98@paulmck-laptop>
 <CANn89iKdJfkPrY1rHjzUn5nPbU5Z+VAuW5Le2PraeVuHVQ264g@mail.gmail.com>
 <0e9dbde7-07eb-45f1-a39c-6cf76f9c252f@paulmck-laptop>
 <20250319-truthful-whispering-moth-d308b4@leitao>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250319-truthful-whispering-moth-d308b4@leitao>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QQSldM6p;       spf=pass
 (google.com: domain of srs0=en1s=wg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender)
 smtp.mailfrom="SRS0=eN1s=WG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Wed, Mar 19, 2025 at 11:12:24AM -0700, Breno Leitao wrote:
> On Wed, Mar 19, 2025 at 09:05:07AM -0700, Paul E. McKenney wrote:
> 
> > > I think we should redesign lockdep_unregister_key() to work on a separately
> > > allocated piece of memory,
> > > then use kfree_rcu() in it.
> > > 
> > > Ie not embed a "struct lock_class_key" in the struct Qdisc, but a pointer to
> > > 
> > > struct ... {
> > >      struct lock_class_key;
> > >      struct rcu_head  rcu;
> > > }
> > 
> > Works for me!
> 
> I've tested a different approach, using synchronize_rcu_expedited()
> instead of synchronize_rcu(), given how critical this function is
> called, and the command performance improves dramatically.
> 
> This approach has some IPI penalties, but, it might be quicker to review
> and get merged, mitigating the network issue.
> 
> Does it sound a bad approach?
> 
> Date:   Wed Mar 19 10:23:56 2025 -0700
> 
>     lockdep: Speed up lockdep_unregister_key() with expedited RCU synchronization
>     
>     lockdep_unregister_key() is called from critical code paths, including
>     sections where rtnl_lock() is held. When replacing a qdisc in a network
>     device, network egress traffic is disabled while __qdisc_destroy() is
>     called for every queue. This function calls lockdep_unregister_key(),
>     which was blocked waiting for synchronize_rcu() to complete.
>     
>     For example, a simple tc command to replace a qdisc could take 13
>     seconds:
>     
>       # time /usr/sbin/tc qdisc replace dev eth0 root handle 0x1234: mq
>         real    0m13.195s
>         user    0m0.001s
>         sys     0m2.746s
>     
>     During this time, network egress is completely frozen while waiting for
>     RCU synchronization.
>     
>     Use synchronize_rcu_expedite() instead to minimize the impact on
>     critical operations like network connectivity changes.
>     
>     Signed-off-by: Breno Leitao <leitao@debian.org>

The IPIs are not fun, but in the interest of getting *some* solution
moving forward...  ;-)

Reviewed-by: Paul E. McKenney <paulmck@kernel.org>

> diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
> index 4470680f02269..96b87f1853f4f 100644
> --- a/kernel/locking/lockdep.c
> +++ b/kernel/locking/lockdep.c
> @@ -6595,8 +6595,10 @@ void lockdep_unregister_key(struct lock_class_key *key)
>  	if (need_callback)
>  		call_rcu(&delayed_free.rcu_head, free_zapped_rcu);
>  
> -	/* Wait until is_dynamic_key() has finished accessing k->hash_entry. */
> -	synchronize_rcu();
> +	/* Wait until is_dynamic_key() has finished accessing k->hash_entry.
> +	 * This needs to be quick, since it is called in critical sections
> +	 */
> +	synchronize_rcu_expedite();
>  }
>  EXPORT_SYMBOL_GPL(lockdep_unregister_key);
>  
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/89ca1978-de9e-4502-8a3b-970ad8fd9fcf%40paulmck-laptop.
