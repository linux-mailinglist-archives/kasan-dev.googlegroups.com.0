Return-Path: <kasan-dev+bncBC7OD3FKWUERBQ6E6GXQMGQEJH64QJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id E7BE0885D9F
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:24 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-5d8df7c5500sf654919a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039043; cv=pass;
        d=google.com; s=arc-20160816;
        b=ftVXC6fXGm2CVBK41cCA8JRgAIguCRn2hjPzUy6dsvSNbDsHzLzhZdvvfwwpwbji3j
         EwT7u8QujbV4p9u1Q2MU3uk4GTuxEjzcxfzemKHVGfAqn/EGOJWqopa+TcZRO97KTRXG
         eFLhKo5wrFnWFF32K8ZB1BWwzdUEoxGvT7ucmKycNsVc67S16UTslso8raq4MrBuYeyk
         Trtng2H834yKOVrFFoHSNw56ee7znU9QBgQBNZ21nzcC8HSVCQL1vaYhp3qd3DDgrP9f
         B0fDjy8YMytXGfFZMbYE4ecHQFSmB+w9xurrpmE0HDExqWVHNn3By057qfqDrhALBk0x
         AU2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=MN+in8Va0EpTBg8XHHZVIcIZO9MW04N045U9YFsyDS8=;
        fh=3zk2klKYtU9YIsAx0qqf0F7UR8zUP2+2BiANLDDae84=;
        b=cV3HvhtnH9HSDMRvnn5bAREKplYAok85sFTNQKLzGX7n4h3iQD65y3kwS2ndVhRuZu
         99FR2+q7W0lZlVisP4qlTjWSOHu4XaNQ4A2PGlNexES3U+wHAjWSfr/zFzklBSXQsbgq
         7S3R7Bt4pwwz8/sPah27A5SRLUsxLYYDm0jF5fFp7st72twtYoPpm9LzjtLQWHKUs3Vr
         eVC92fB+Krbi/FJ3/IZYJN7xRox9iIOiFnpIeR0cUOuclbmFahpmEECE1p0v7GCCTcTr
         pGvhXQ+zb9Q1AZDA1DlUbqvYFOuyhaCo07qyEKBSvlZ6Z8I+eE9oW2u0oJCuyvWV3ZA9
         fgOw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=C+kjcY17;
       spf=pass (google.com: domain of 3qgl8zqykcs0bdanwkpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3QGL8ZQYKCS0bdaNWKPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039043; x=1711643843; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=MN+in8Va0EpTBg8XHHZVIcIZO9MW04N045U9YFsyDS8=;
        b=sYcOAaVdxOX+sjLT3i5gS75diGOp90uuKnVbM5OvvRsU1PFoFPd6jbD2BsU1+tN+nb
         1EGYIoZYB91p77MMrXRTCNyA0ZNYEvb+9cXRYFekMShn0CDcOSajQFLMWIoxpLBnijSz
         gFdYIvAOAk/8kQz/mPhUB5oRkEJoKO5oyOj0k7HMHx12pRacvVtRZ4OY9sOcD441oQCE
         1gmvd9KBRDzn8pUhuGy24H+yqrwK61VfrUoV+d5jykEhh7yYHov/9ybt4FOTM7gvxhMi
         QaiyiOg7fPM7eJeo6Fn1MvB2scB63KiDPHAEZ3h0nHWAE/ytJx2ZiHxUBQ1esBNx0lop
         8x0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039043; x=1711643843;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MN+in8Va0EpTBg8XHHZVIcIZO9MW04N045U9YFsyDS8=;
        b=BifRSStVrdxb4woMjEkKcdKTJjwQiG7Vr+4phJXh9UUOdP1gegTqHT/VCKRjlniZwE
         Qhp1BV7RL9NHD0DS26HkGmEoUaXFbP+8b36lTlLWbIHrYzTNhVl4NQMTRuFR89rvIU/e
         LdBob4fTEXipSwHcwrP1TGdw9BC67K3iBRXdw2d6ktUBc1gh2cT0gRF93B2CH0j45qQ6
         1moO7HqTxzaAsk3lLNL3+WcuvyJKQ2li4LV6npML3DUSEx5tlLVPxSlpeByn65CeYviK
         CJ3XQMxL4h8P242rZb2D3CENq5oW57wxIzu3Au9mV8Sfw7xAv+oi9ikcBz9uBZcjqMsG
         WepA==
X-Forwarded-Encrypted: i=2; AJvYcCU/cvIaASWJGLTY74tiHk1i3ewwPFnGp/AWDW6LLrg6XW8SjDrkiGPXOB57k0F8HUSGD3zvbStPYwzY14zsNWKacfB6LyN8NQ==
X-Gm-Message-State: AOJu0Yzbf0e/4rrixT+rSYfqSUuVJA5grWFQ/FP30ioEaF1iYVLrgqpy
	+YZsk3y13KhFAjD9FDEift9f0vUTJlJwCYM92EHu33iS4uW/7Ah7
X-Google-Smtp-Source: AGHT+IER6HJQOVvVSPvKt/h1hjQDjly5hbUwUTYyX+4n6MPk8S6f73DTTN28qleZXeSfdDvK9s8R/w==
X-Received: by 2002:a17:902:f60b:b0:1e0:7f78:624d with SMTP id n11-20020a170902f60b00b001e07f78624dmr1518872plg.57.1711039043402;
        Thu, 21 Mar 2024 09:37:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2444:b0:1dd:a467:24c5 with SMTP id
 l4-20020a170903244400b001dda46724c5ls790186pls.2.-pod-prod-09-us; Thu, 21 Mar
 2024 09:37:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXOn8+aAXQfo5/VsE5I3xM9XSpJksKaBcGhTrJ+0EX+yjdHiE1+SGndI7UUXt+V1gB5B3F3z+Q2t0xgB7tVII9UflreU5adlC/LwA==
X-Received: by 2002:a17:90a:5288:b0:29f:988d:c980 with SMTP id w8-20020a17090a528800b0029f988dc980mr9422745pjh.6.1711039042084;
        Thu, 21 Mar 2024 09:37:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039042; cv=none;
        d=google.com; s=arc-20160816;
        b=wtv6zGWjW7Ooq6War/4P6Rv0SuOMdSH1sLPqXnykiZdntOPko+PdIhoi7fm14WJ54X
         IgSSi/DMHbXDPeVeHwquKaaVkQX8sgcEVsPsKVV9dBWZFdsaWqDVpSqgZEstiQb4uHsj
         5H6kmqz/rrYpVWN4FGj43SsOtBebmQsrqFSP7WRWf6yunnxLH3KkoV8xiPXtDi9+UlW/
         26LRZne6wSxfP+OWvCpoS9MThyh1zOm0UBrccZ40XUYG64Jboh/lu4YilQZvGZ7Hst/s
         PKLhUEuMab0u/az7kipbQ2SdqyaBIeMbC3itaoOOKPbecKI0AXpQdk+XNW/kP43DbpV3
         RYLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=jDSqL7VR8RZR1D2YCsFy3ymp62hocq5f4M4VfhBDRaA=;
        fh=Ixd2QVivBxaGwy3btTQejHwYPg91B4HfBUhAPGws+sA=;
        b=nKbH89K/iwAl7sTcWphlog048bPsM3MCLTtOHhmYV5u6TPQ3w539TcydXxCd0l9VJ4
         Rgz6E/1gYhgOMEUs0oJDQBrtORI7e9JkQPlDMoXZYHcYVpg4zQ6c4u9Qq2WKNQz3l/t0
         SuRIyulSrBRG52NNYZw4anSBoN3wJzFXHvnILN3vz5+kdnfTjdKiSZ4o/LMN2648RTlT
         vW59VSzl6KCN65BKudMfe7dLBDFhqR5S+0EPEp3NGOC43KD1Z40r2kpN7H+8Ot5vdOVe
         TDK+wZYrg3p78RJdup6qft904WwTanEZGTAkUtZf3dmWEp1wsubdbhW3GCfgbo9gjoTr
         Kdzg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=C+kjcY17;
       spf=pass (google.com: domain of 3qgl8zqykcs0bdanwkpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3QGL8ZQYKCS0bdaNWKPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id s7-20020a17090aad8700b002a005b22a6fsi32851pjq.1.2024.03.21.09.37.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qgl8zqykcs0bdanwkpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dc6dbdcfd39so2285210276.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWZPramsFd/dxeoOtnQUspsZQ0Ivz9Uei9+L0QMnQoo5CEvn0Fx7al25X4Dpok0Yjvkv+mNoMWmLdOd75KHC+U3aSqm9MoYraWjTw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:703:b0:dc2:550b:a4f4 with SMTP id
 k3-20020a056902070300b00dc2550ba4f4mr5784120ybt.1.1711039040945; Thu, 21 Mar
 2024 09:37:20 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:27 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-6-surenb@google.com>
Subject: [PATCH v6 05/37] fs: Convert alloc_inode_sb() to a macro
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, Alexander Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=C+kjcY17;       spf=pass
 (google.com: domain of 3qgl8zqykcs0bdanwkpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3QGL8ZQYKCS0bdaNWKPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

We're introducing alloc tagging, which tracks memory allocations by
callsite. Converting alloc_inode_sb() to a macro means allocations will
be tracked by its caller, which is a bit more useful.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>
Reviewed-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>
---
 include/linux/fs.h | 6 +-----
 1 file changed, 1 insertion(+), 5 deletions(-)

diff --git a/include/linux/fs.h b/include/linux/fs.h
index 00fc429b0af0..034f0c918eea 100644
--- a/include/linux/fs.h
+++ b/include/linux/fs.h
@@ -3083,11 +3083,7 @@ int setattr_should_drop_sgid(struct mnt_idmap *idmap,
  * This must be used for allocating filesystems specific inodes to set
  * up the inode reclaim context correctly.
  */
-static inline void *
-alloc_inode_sb(struct super_block *sb, struct kmem_cache *cache, gfp_t gfp)
-{
-	return kmem_cache_alloc_lru(cache, &sb->s_inode_lru, gfp);
-}
+#define alloc_inode_sb(_sb, _cache, _gfp) kmem_cache_alloc_lru(_cache, &_sb->s_inode_lru, _gfp)
 
 extern void __insert_inode_hash(struct inode *, unsigned long hashval);
 static inline void insert_inode_hash(struct inode *inode)
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-6-surenb%40google.com.
