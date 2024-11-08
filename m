Return-Path: <kasan-dev+bncBCKLNNXAXYFBBEWWW64QMGQEUIV6WEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id CB5ED9C1AE2
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Nov 2024 11:42:27 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id a640c23a62f3a-a9a01cba9f7sf142375966b.3
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Nov 2024 02:42:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731062547; cv=pass;
        d=google.com; s=arc-20240605;
        b=I9ocLj1qy9ll5bfcoMR8x6WA/K4X5msYl5n0ERpkn3ZGuOvH1vU6g6csRHTHhbGmTb
         GIawKM0EehRpMKJ89WORpIkjGUTnpjS6HJI47h9qxrBwQWYR95HtajvW+Dr2KLs09kMs
         78rvGKKV/ZgpjKP33p8yaHGJn6ae7wDJjvX94Ah+CtoVS6r6RUqtHB3BA6x4QY7k0Id3
         Bz9moAO7XdRl92OyQuAh7InvzdFnDSNf8U3vU/jw1A3LJ0TngBKrT6pOw1GPYQypsVfH
         GXreZ2NVIrF/l5JhkBnf7jJRNnKZ5pnsnO337N8Sm/emr+7nEzHl4h/49A3bujp2Cz4V
         SNWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=U4wAwzMmYLhPmxfQxAORp1fiWiGnvoeegCORkP+K8KQ=;
        fh=Of/Wbveox6LpUFCfRcvDwh65b9Qt+EF/J0flfH3/vBE=;
        b=Pe3x7sQGXLu+0JFpuQ9w66MoLSb3TnIdGHNbOzW7UY89sHKVgHNSBxI5aiKbANJfda
         nngT/9YMS8HoCMvRzmKegS58PYzaSijpzP7MSjM6g1rpA80xOGy3tbRE+OdqGXuIDJIl
         bn0iYfHmyJm25mzsdnHozilE9iDjRYkApzhwT2rIVjxSti/oqPJw6+XEnbRFf/3qXa/z
         7kZyFHWXrSZrALxB6JOyB8H+FqqEgMcal1hTXfeonwPeuxcOkML3Yv9eN4IJvaxsUxGT
         GsCujLereXZU0fVQFO84iIv0AOrBhhSBT08I3LrregYu74cbx/ovH6ZReU/zscia811l
         Uy7A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=hhcP8+Wo;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731062547; x=1731667347; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=U4wAwzMmYLhPmxfQxAORp1fiWiGnvoeegCORkP+K8KQ=;
        b=Va6wTzdGAvQZAEWAPuVuYENqvuQmOUWnoThm3j/dPXiUFLrbo8xLfCAQiNl2Wkf0pW
         d/UKB85QNEh4pqPohb2ua/cXHou0eY2+Tb8UMnaVZFfrb0PA6A1lQZBBdKCVb3g5ZDF4
         2NHU8iq1u3RBiVJ/9wmxEQvb7ScUAYnYcgb3pGnpnTOM2XRlMhmn6aeZZicPkPsvjZQX
         o7K5h4agkeZqvbe/fNaIpF0jJxmHF8YaHhnIVsY0mj+WUs8KsY41lh+jVTAxGfk+tAJQ
         Vh9ajWv87wayxTh7rFAPMM21B7qZwVxGkEUsOO4vectteGQwln+tS2vOf4YhTVr11F6i
         WE6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731062547; x=1731667347;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=U4wAwzMmYLhPmxfQxAORp1fiWiGnvoeegCORkP+K8KQ=;
        b=w2CVT0T1JnQ7vCfxgNzNYgnUD7Gb+JQKFcbaZNwWlU7srqoURRayufUv8yl2TYSPSn
         V8/EkpAWqZPZQAi7ZXtePvbF20ByjrE1wwtCZi6F7RGHU7K7WgG8mh0B2TDnNzQKm0VA
         ey1DzIXf8eXezJcDiCsy22zleZnAweMX9c1L11iTOJZN72mTTyMve1rT1HuZYxnJ8Dvl
         e5H47vR4uy/q7TR9PqWElBt1lqMVr8OZ6mP/4sznLgnjl4TVC7ajHWWDkCGb6MnHH4WL
         F4hcEAMRSWI7/lIxjwCF/DKCMEoArozhxp1ocKrciLP0wX/eV7hhXlnifaKt/KKwtCAO
         1aVA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV6YmoDlVopgLW8BMnfhvc2qYRrvBOkXr5rahjQO+nG+A8aO2eN/+HFbUANdaxsqKAMsRHnqg==@lfdr.de
X-Gm-Message-State: AOJu0YzgR9ZD+NczkxQvi+lvH/ODypqSgfz97T0U7UAkp3jLgLZR6Giz
	T/QIlgWPCEw1V/K8+0H28VSkmflEAe4g5Ma6REeO7QFHYNf1ZXML
X-Google-Smtp-Source: AGHT+IH+TxqclLKhH3KMT/6KWufKWEl67Sp3bie/XqQSQR7BUZVkz20AT4vBjYIUz9aZRP6GKbYgSA==
X-Received: by 2002:a17:907:1c10:b0:a9a:7f84:93e3 with SMTP id a640c23a62f3a-a9eefee9bd2mr178022566b.14.1731062546532;
        Fri, 08 Nov 2024 02:42:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5609:b0:430:5356:aca3 with SMTP id
 5b1f17b1804b1-432aef5d467ls1702065e9.0.-pod-prod-06-eu; Fri, 08 Nov 2024
 02:42:24 -0800 (PST)
X-Received: by 2002:a05:600c:3514:b0:42e:8d0d:bca5 with SMTP id 5b1f17b1804b1-432b74fdb3cmr16982155e9.2.1731062544007;
        Fri, 08 Nov 2024 02:42:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731062543; cv=none;
        d=google.com; s=arc-20240605;
        b=Vj9viVzZWLi5MGdd41MVigo94DwwDw52b121wqTEC2u6Aah9NQhaVKJE/UVMpPN89k
         kN13r2t/kVnu3QwmepZ2MsQYwAGvqE5qQTXk7pGWrqTNGNYBtPfg5wg4+JK4M45lDMci
         2ScwXQc6t2f4+wKpx1QlJHvxtZrtilSCGg1Snfm+y/3FobA72XyGW9cdWbICqh8uzH0u
         SpWaj8hJr/8xIVlEZZd9awZlyiUg7kGBtQ0EeRVsJnOXLJaDGclMqk8teLXPIWpB0IV7
         igdH3beU8IYd+izy3NP+rjqEjQxwLCIUG+6lnGhK8sxhF5USJ0TINtPTUPA7zlsn5OGq
         TmuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=hZ7T3n9ji38bfDcEZMnrKQTiWeEv9uEaf9nIoN35Fps=;
        fh=iWXmJmSNHIKwihjAFTZHxJXx+Bx4TM7umj/iDaR++1w=;
        b=cBsNvzCPi6855rH+vu0FYzkzvxOiCZF2N/mzD/3pMGf1rqXO8MEfQYaVJbvNPdq0Nc
         xeTNg9S6rA+QDGN/rv8RBYzo9+5luQX+b9fE2evOnLZtex8zvQam+Qu7fe3RNDxEZZN9
         87voSy5Ro9i+YEZDeWco9rwncH0FURR/tz5Es6jSUynF4LutNRpFzGru3yGfAJbzjzRC
         0YPB/zEmUlk+/Gxyj9gjIyEP7ItN6xJb/WtB5OU+DCfyuwccJ35pk8tRExwElRvE3kGp
         LMTWE8nt0kXBK1Qvor+HOWc0XvA83TNf3zXcQ8+PToq53RF7ZVUUTW4ct4D4qJYocsq6
         YEow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=hhcP8+Wo;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-432a3686ceesi6370585e9.1.2024.11.08.02.42.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Nov 2024 02:42:23 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>,
	Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Tomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>,
	akpm@linux-foundation.org,
	cl@linux.com,
	iamjoonsoo.kim@lge.com,
	longman@redhat.com,
	penberg@kernel.org,
	rientjes@google.com,
	sfr@canb.auug.org.au,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: [PATCH v3 2/4] scftorture: Wait until scf_cleanup_handler() completes.
Date: Fri,  8 Nov 2024 11:39:32 +0100
Message-ID: <20241108104217.3759904-3-bigeasy@linutronix.de>
In-Reply-To: <20241108104217.3759904-1-bigeasy@linutronix.de>
References: <20241108104217.3759904-1-bigeasy@linutronix.de>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=hhcP8+Wo;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as
 permitted sender) smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Content-Type: text/plain; charset="UTF-8"
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

The smp_call_function() needs to be invoked with the wait flag set to
wait until scf_cleanup_handler() is done. This ensures that all SMP
function calls, that have been queued earlier, complete at this point.

Tested-by: Paul E. McKenney <paulmck@kernel.org>
Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
 kernel/scftorture.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/scftorture.c b/kernel/scftorture.c
index 455cbff35a1a2..654702f75c54b 100644
--- a/kernel/scftorture.c
+++ b/kernel/scftorture.c
@@ -523,7 +523,7 @@ static void scf_torture_cleanup(void)
 			torture_stop_kthread("scftorture_invoker", scf_stats_p[i].task);
 	else
 		goto end;
-	smp_call_function(scf_cleanup_handler, NULL, 0);
+	smp_call_function(scf_cleanup_handler, NULL, 1);
 	torture_stop_kthread(scf_torture_stats, scf_torture_stats_task);
 	scf_torture_stats_print();  // -After- the stats thread is stopped!
 	kfree(scf_stats_p);  // -After- the last stats print has completed!
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241108104217.3759904-3-bigeasy%40linutronix.de.
