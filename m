Return-Path: <kasan-dev+bncBDTMJ55N44FBBDMS5S7AMGQESPLFGCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AA43A6979E
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 19:12:31 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-43d00017e9dsf29646655e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 11:12:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742407951; cv=pass;
        d=google.com; s=arc-20240605;
        b=e0Q5XzjGyZ9VAsYeVkV5pN1SyZSZcBpkOT8gJm2WvEhdkRjHFG47M/Zpt8K/jVeHI0
         CkxjuzX24Diyt0deocy+rl9/Zk1aazSHSQiVypPlrtJSkqwPPZ/13dr1YDt1RfpyIkFT
         anfmkmIYgyK7XPRIV7kameA6ViLOdsUowwq0SdHsV/dw6ndKltDG1IJINOJbAxxzZ2XM
         NG3KuVyiW4CpXjFyJ+X/hPxv1DNJFxHyqDo5Rxc1cQTFYeGvRs7gzQSs6o7nlU8jOC2T
         mav3cVMYejBQEZLHdbNCIRMbj2+jYz3iUynYzSX9dpe+neZIng+HfVNPA2iasemnLCAQ
         e47A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Ak1rY+qT0qaAYdFNslnZuGQrLKo/vsg5JRyoZd4IB+U=;
        fh=dLoDEtrpqKiCpOrOUsnQlKWHm8v+O8xiRhYTOgmGCj0=;
        b=TyzKwB9rQBa/GKwRMmsFfe3ZFhbCdI53OMc0lSc323XYGaOQZnCdGGaLnuAgQfP9Z5
         fqTQA865GecGUhu8J/wc8L2Amc2MGIRr5oYfrtFtKyMGH7fxYOOl6TJezf65DkEpsVDM
         a5YJj8aIefJK9fPrZlhvb7ys2MGtFARXgFQvNopa45fofp4Vs2aSV11TKBc8jgUZupo7
         ANiX/Q7uD1ii2mnBwjDXBefW7wmCloj5QTIwejQpDxK6mcoCEKdrXJWK7ayai1HVV5a9
         FVj3KnyIdhS8uCvqlf/4Kj4QZoOrsv0e1w+xkrNSFCDSAvkwr3UfDyWNf9BXjPSWA0lP
         aOEQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.50 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742407951; x=1743012751; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ak1rY+qT0qaAYdFNslnZuGQrLKo/vsg5JRyoZd4IB+U=;
        b=muS8IVrqXiQ+HNcqJLyW/xY3glCLmhc1iFRPFqGjv0Kng9moK3kFRPIZkJnGkPqzQC
         N1tXe/B6LMnV1Osa/+9r+SE8Mh3IR7zB7AGnDXafobP4cLZW11ssyalekVFaF9JVZhom
         RKHgLy6g/7uWCnaM3p1u1qYxXkZHwjyHSslOcqlW9iy1eRDdYSjyQSk7Vc7xCgqZZbPS
         UQt15pEwvkYcq3qqemeDrBJZq0pOk9gwQd0JV2e9iPS/vwoiBMTRvlIOAPqzxdHMEj23
         x/CmDtxrIhpXbSqj9EtYU3MZA5maX/wFB0YqELibaw/3xqs3+k2HgjRd75yLZdOievEF
         7vTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742407951; x=1743012751;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ak1rY+qT0qaAYdFNslnZuGQrLKo/vsg5JRyoZd4IB+U=;
        b=QlOdlAItHUmgw5xGQVXp2n7Khy+xdVgf+f+C37+L3472tiGfl8om6c6mpYAkZK4aBG
         eIec1PC9eNf4DaOdvbtqIKuG9F5TjcroTtiSSi0SupyxI2LlFeCvJ+tLwa1Alx8nCjZW
         zTw+SLng0FFT7tZqBmf1Qx1q0EaGJE5e7E22hFSI6691jR0zMUZeBVHP4sdy43iecnEZ
         N5w1hND50iw7CbFt2cvHiQbpESkLwuPJeoUw54gSvUvoVBs0S8loP2w0eSfXxL9QL4HK
         V13k1WLo8dizGglYShwy11CkRKrNCoVzg/SR7qz+X/US3DvEZp/XJsxlPxdscChHWsi8
         z2yA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXOi8Ce4F4pQ9sdqAvFhD4zDFn+xpfIx8uRM20PBJERCWotg90IBEMSwqwU6qXi5b13hquLsw==@lfdr.de
X-Gm-Message-State: AOJu0YwSOfduHAcJlMueIe1xSlAUFfbd0fO0UI9gBYsFnTNtHnuqIYPD
	IyVRyWcNucueiPdPP6lQk2QUuTOUZ5G3rTtrfgZt2dwZzak1InnB
X-Google-Smtp-Source: AGHT+IE5R1scjHppQRL5AQVbM+oVJVv1SlCcyk07alFn+1hcr7IGgpMEYulCnSobavY6DUArywIseg==
X-Received: by 2002:a05:6000:1867:b0:391:39ea:7866 with SMTP id ffacd0b85a97d-399739c814fmr3981235f8f.19.1742407950297;
        Wed, 19 Mar 2025 11:12:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIXdbzPq1a5LWYw4aMiRC43pG4Ydst2i9vOLSeG/EdrDQ==
Received: by 2002:adf:e701:0:b0:38d:c1e5:15ce with SMTP id ffacd0b85a97d-39979705968ls42941f8f.2.-pod-prod-03-eu;
 Wed, 19 Mar 2025 11:12:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUnmRZI1za9AbmT1BpGk7abi87jbbsKWaq86NIWJZg6fwbdyvJFTdhN+l/R5lRcsFwo6iTMT/YCrHQ=@googlegroups.com
X-Received: by 2002:a05:600c:b9b:b0:43c:e70d:4504 with SMTP id 5b1f17b1804b1-43d43842251mr31705975e9.19.1742407947667;
        Wed, 19 Mar 2025 11:12:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742407947; cv=none;
        d=google.com; s=arc-20240605;
        b=eGV+ad5UYb/hsLn3Xhzsz49CRx3htLPr7qJRpt0gi3VuDQ2x+bWpHSL0+T9s1f9C05
         UOaf6QWYPx/FWu3zautFhHlw7z2Td5aV3fddZZz4k9F+PvtXvI3+TpCVCXQAbcFRQDZm
         S9hUaCbp4AiSS9wBOi1HoFAVF4alvuMDrYuWpZ4ZONDJTkrEC/umxwde3Q4y7JVtZbBb
         t5mOQ+cNV9KuuzWcDFqBAhEpBc7eV0VY0ukFlNCh9dh4+nNk5HSfVmUsZyYvxphxOfUY
         E8IwnSHaTqDvH44hr99HQkEw4OszoA5f0Z7yuT6L1wCzyJPCs1gVogndqHDbYqv2AAvZ
         9S5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=7Up1xjea84mFFtC/QFUl+9GqZdL4YQBVY41iIzJ7s9w=;
        fh=Hq1HVmeyGgV6iJafh9PgRVYtywp/dx/AdZmqP3NiLVU=;
        b=Sy+qaCq60wfuAFr6zItLI7ZFoUXNBpvRao1jCFMj0GiBP8F6vSfIONsmRxO69auiJl
         l9iAaofsHmYbMfMUcwKT7nwqJ+A2qt8+QR/B0zrSpEXKzII7P0volbbwO2AUsbcNo/OY
         4/JX3RQMibLflmWkv4xBeGkSCO44ug2/4gBNnY2PKrs7DM3xUxe7YBzSPIFcatWsdy92
         KpxoKlNOpDP2Da6LDdMP3bEuXXoqSTpTl/eIXWDXbMLfqdsgYJjqf7eLguTmGxIXwItB
         /hBxiBnpnxelY0TIEcxMJf0KNAli5KhnvFQyMk0m/vucwjEMdICz0xayl34E++5aXsNN
         6NKg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.50 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-ed1-f50.google.com (mail-ed1-f50.google.com. [209.85.208.50])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43d43d80b5esi397715e9.0.2025.03.19.11.12.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Mar 2025 11:12:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.50 as permitted sender) client-ip=209.85.208.50;
Received: by mail-ed1-f50.google.com with SMTP id 4fb4d7f45d1cf-5e5cd420781so13455761a12.2
        for <kasan-dev@googlegroups.com>; Wed, 19 Mar 2025 11:12:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUn91HADcqZMahQiMqUCvk6UmPVTpLA7iQhWTDizOc1fA7DSO1JkUZxnjuvmHR4rAfJgyp//5QgRX4=@googlegroups.com
X-Gm-Gg: ASbGncu+UvAcCMacUpMW5SUTbF/hh3u8XJtaKeaY5hxTaxzKahRU8BC7M3WrI5VK+tQ
	t3S0j804CY2NRzboJcWi+WKsaqdMuhs7GHnlNqw/OcqeO+9Rw1PpUWd47Apgb8bNQ6Zs2c+raj0
	CKLfkgplRDUxUr4SZgh+GpELR81jAXWP2g48tDbzoEva7+d18yST/dW+hLynQh6mRmx2i38A6Ot
	jVWZ4jvGOTDDE0scvQ9FXhzft7h8bQ3wINp8cm3yrCDkzr2vXJ+SBGOjZgRzSjNnppqnGwGHY9J
	LHlc/TAfbxJnR2jYkgRAJLySdez16Y4KzmY=
X-Received: by 2002:a17:907:9706:b0:ac3:3fe3:bea5 with SMTP id a640c23a62f3a-ac3b7f73116mr326822966b.38.1742407946951;
        Wed, 19 Mar 2025 11:12:26 -0700 (PDT)
Received: from gmail.com ([2a03:2880:30ff:4::])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-5e816968c0csm9466508a12.22.2025.03.19.11.12.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Mar 2025 11:12:26 -0700 (PDT)
Date: Wed, 19 Mar 2025 11:12:24 -0700
From: Breno Leitao <leitao@debian.org>
To: "Paul E. McKenney" <paulmck@kernel.org>, longman@redhat.com,
	bvanassche@acm.org
Cc: Eric Dumazet <edumazet@google.com>, kuba@kernel.org, jhs@mojatatu.com,
	xiyou.wangcong@gmail.com, jiri@resnulli.us, kuniyu@amazon.com,
	rcu@vger.kernel.org, kasan-dev@googlegroups.com,
	netdev@vger.kernel.org
Subject: Re: tc: network egress frozen during qdisc update with debug kernel
Message-ID: <20250319-truthful-whispering-moth-d308b4@leitao>
References: <20250319-meticulous-succinct-mule-ddabc5@leitao>
 <CANn89iLRePLUiBe7LKYTUsnVAOs832Hk9oM8Fb_wnJubhAZnYA@mail.gmail.com>
 <20250319-sloppy-active-bonobo-f49d8e@leitao>
 <5e0527e8-c92e-4dfb-8dc7-afe909fb2f98@paulmck-laptop>
 <CANn89iKdJfkPrY1rHjzUn5nPbU5Z+VAuW5Le2PraeVuHVQ264g@mail.gmail.com>
 <0e9dbde7-07eb-45f1-a39c-6cf76f9c252f@paulmck-laptop>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0e9dbde7-07eb-45f1-a39c-6cf76f9c252f@paulmck-laptop>
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.208.50 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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

On Wed, Mar 19, 2025 at 09:05:07AM -0700, Paul E. McKenney wrote:

> > I think we should redesign lockdep_unregister_key() to work on a separately
> > allocated piece of memory,
> > then use kfree_rcu() in it.
> > 
> > Ie not embed a "struct lock_class_key" in the struct Qdisc, but a pointer to
> > 
> > struct ... {
> >      struct lock_class_key;
> >      struct rcu_head  rcu;
> > }
> 
> Works for me!

I've tested a different approach, using synchronize_rcu_expedited()
instead of synchronize_rcu(), given how critical this function is
called, and the command performance improves dramatically.

This approach has some IPI penalties, but, it might be quicker to review
and get merged, mitigating the network issue.

Does it sound a bad approach?

Date:   Wed Mar 19 10:23:56 2025 -0700

    lockdep: Speed up lockdep_unregister_key() with expedited RCU synchronization
    
    lockdep_unregister_key() is called from critical code paths, including
    sections where rtnl_lock() is held. When replacing a qdisc in a network
    device, network egress traffic is disabled while __qdisc_destroy() is
    called for every queue. This function calls lockdep_unregister_key(),
    which was blocked waiting for synchronize_rcu() to complete.
    
    For example, a simple tc command to replace a qdisc could take 13
    seconds:
    
      # time /usr/sbin/tc qdisc replace dev eth0 root handle 0x1234: mq
        real    0m13.195s
        user    0m0.001s
        sys     0m2.746s
    
    During this time, network egress is completely frozen while waiting for
    RCU synchronization.
    
    Use synchronize_rcu_expedite() instead to minimize the impact on
    critical operations like network connectivity changes.
    
    Signed-off-by: Breno Leitao <leitao@debian.org>

diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
index 4470680f02269..96b87f1853f4f 100644
--- a/kernel/locking/lockdep.c
+++ b/kernel/locking/lockdep.c
@@ -6595,8 +6595,10 @@ void lockdep_unregister_key(struct lock_class_key *key)
 	if (need_callback)
 		call_rcu(&delayed_free.rcu_head, free_zapped_rcu);
 
-	/* Wait until is_dynamic_key() has finished accessing k->hash_entry. */
-	synchronize_rcu();
+	/* Wait until is_dynamic_key() has finished accessing k->hash_entry.
+	 * This needs to be quick, since it is called in critical sections
+	 */
+	synchronize_rcu_expedite();
 }
 EXPORT_SYMBOL_GPL(lockdep_unregister_key);
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250319-truthful-whispering-moth-d308b4%40leitao.
