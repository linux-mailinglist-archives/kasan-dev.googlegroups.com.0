Return-Path: <kasan-dev+bncBC7OD3FKWUERB6FD3GXAMGQEN2NIB3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A4D285E78B
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:45 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-365123e460fsf34105ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544504; cv=pass;
        d=google.com; s=arc-20160816;
        b=GVOAHV0gw57+a1HISW4kCT/kSdXpgzlN/fNDgKq68jvilnt/pdEt32y4bvtLzGAE5+
         OE97q0CbagpQ4NAIATogldUaKZGk/X8JU7L3WC1O1EiEMDBmSjMzj6Z6wlTX3ULUX43h
         fuKI5Y5NTDRYPaqbtYkW2T1iOgmJYYNKVPl3LkCS7Ai2HevLWGKZBr0oKIk+6+R4Rm4Z
         583wpNAVgPHxEVhANWidS68OWmP54/rRS5r1gdusk2peWqyEB1qwINe8Cd5myWr/DzyW
         SvMVba4YI0DXic6ga+SfkrqcvSvtWEo4I0cWEuA2X/o0IQeRIqAfY/SUXsPZA/P/NxvO
         oa8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=k8nRnDSMb2WT558V4nJGJqKnAZ6ti9PRlK91f9UftE0=;
        fh=pZQ0B8ZHwa/ce87DynY4YIvRe1HQdngXkg2oaRduiWw=;
        b=g+xT/2jtY0yaGur4afUnBuv7UBKbMs2OI3HVssK/KXlpziOYUSgsRgTcGLToTqSgej
         OZwgfLbUrZgdQiRvltYLzyBLGDo3BAceicaWfuViJk6CxbwuJsWVMjfq/+DoLvH6Yqdf
         0a1rNNIJLB9E8axBFcJ0b8Mnhhug3CK/LuBa1865vMLE8wFhHIWcXSVrsqD0gjTqx9nN
         Qa/4rkjzm74T0KcsK5evvdpw35YMf35AbHqQvLIZpmz5muMsFLl/qxOeNcb3yDAOHX/3
         l9ADFTHYiRwR+vmCU/SThDoWgybUnq3zLiYtuBTpyh19GHtS/wMuTbpTDPHe+GIYAOYJ
         dTwA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=E7Jjj7c4;
       spf=pass (google.com: domain of 39lhwzqykcskxzwjsglttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=39lHWZQYKCSkXZWJSGLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544504; x=1709149304; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=k8nRnDSMb2WT558V4nJGJqKnAZ6ti9PRlK91f9UftE0=;
        b=BNxxOY+LhIMMeVoWLk+uaFS2oDjNc54uWmhC4CPuek5Ek8L6k3EeUnpO2Z/CwHt/rh
         ZBXy96Ik4dNt96giRX0p5sS1qd0fOtT/AZTqNEZIyvRaINWIT71i2TjSOBVn0r0NvBvZ
         WZ5rKzEYI95iW8HGqQd2kyI0TyWqWWeFOo5kQmRYWNiYLXevI7hg/FB3rVgWNjL4Csvb
         YIoOZg98gEShARlZZqS9gsiDVmlinIDh2JjUWa9l8vgNup/EmaqLCqC2+8zCUuJpf/9p
         LTzwaiTbqQRpltK28/+8zW13Sj4eaSXr+FXX7kJM1HEXVq1KwNRBvBYpJSAFN5q9meBX
         qGWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544504; x=1709149304;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=k8nRnDSMb2WT558V4nJGJqKnAZ6ti9PRlK91f9UftE0=;
        b=kLCgaEyPt7FnW+onDQ7s1HBNTb4b1eEHYscSxY9xkW/Fr/nEXAXK1AtEsMQGWs7rIV
         NpHoBc73YbYLFnqpaB/5Dr09ayEhrdCufYux93kyJjo7x3+p8Tyfz6ImmAEE+h4F6iW9
         ONzYFI8uY8CCPfYBsFSNZQ8ItoDju/aWROEHOf0kjp1mMNrNK090jQenbjCOQmj+Ip8u
         htTQfQPtVFXHYYzOZO86r3iHMPYDb0SVV05gIBoa45jbdd2CCMRt7GqhxMz9FeqEj4Al
         EYJWUHlAaYJC50MhLhG2twtpA5PSYeCJNkpbOQafpkRWc/r1y/exSgOZms8S+2uuARRn
         y3tA==
X-Forwarded-Encrypted: i=2; AJvYcCWv+uV2Q1yPkRuvtUXbyQSejs9CWeJ+LTk3qox4kHnP5gWBcFH9KK5eeBxVwyVqY4cMDR8/T8brk3vsok1oj4CJDHXQvz3bxw==
X-Gm-Message-State: AOJu0Yyec1EQe6iKSRHAJoeiNZTjN4DT2yE6IHbQ8MM1tFWuit0eNn7V
	IGoj8ZYmpReibxQUTatxadHUn8AbBlvt02J36Leha0G3SijuRo8S
X-Google-Smtp-Source: AGHT+IExG5g03iwoJkMPXxkKmi064GEcVEY+NVO1VakZBGcUaTjTN7pGK19cwjzHcgM0cyKyiIrGug==
X-Received: by 2002:a05:6e02:3389:b0:365:1a4b:38d0 with SMTP id bn9-20020a056e02338900b003651a4b38d0mr349888ilb.26.1708544504322;
        Wed, 21 Feb 2024 11:41:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:612a:b0:21a:8286:b50 with SMTP id
 s42-20020a056870612a00b0021a82860b50ls1297859oae.1.-pod-prod-04-us; Wed, 21
 Feb 2024 11:41:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUCDr1ivtIKtCmygGubk82vo9q0mxxsLOppSi2MmoPeJwME8KlfwfvRi/IdX70o/2JIr0SGX7Lg6zkhZmjKfoh9zGkhBuSS1uKTbA==
X-Received: by 2002:a05:6870:8a0d:b0:21e:8fb4:966a with SMTP id p13-20020a0568708a0d00b0021e8fb4966amr14070184oaq.43.1708544503414;
        Wed, 21 Feb 2024 11:41:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544503; cv=none;
        d=google.com; s=arc-20160816;
        b=AgIDUKAJ0vCgVrupOW+3sTGYDT5sYBFqXPpaUpRP6SxdDuxB1CRIVWA36nb7X6ZQwP
         FKf6LVCh6Yge5nn+Q11H34tWySnrAe6rEL5+T2BD8QhkrTZAX2ILy9g97QmiYwLUZXON
         Pmg1jSCRp89CdjBsR2O0TnG9u3JyzZ2gF1aEaKH6YTkXdqav16pajFI6x5z6UNHTlLsf
         UZxtYyqF9yLnlrXbbOnbyOeyyig83xoOhi8p15rkL1e6hwkAXrPvuyy0DHZtks2SLlr3
         R+jlnnyJebd8SzPRBvsYThMS0RfxI8x5NpUti8ZPrLfEfgQc9yglafjbaX9QHMzwSxtO
         Yc5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=4D2ym4tmaIuNf1w08quK73QR9EK/cyrgSXHS1sTLYhg=;
        fh=tleEVI0BjtjFKe1aftucweGsvKnvp5Uj4RK4cc8wh1c=;
        b=YG8hdmKeiBKAxPd1ur+5XGepE9YIyPEqHkcFIUDEJy/H1BPnZEL+GWtGnpcM63rk0y
         w7lqkqee/3QdYVN/P+mnUi3YqiAN0gTCQGvROO7mNcVw9l4bqP6a9adpyJzEvIf3QLRV
         xshfvtcoVcsaUnCiQQ64s6VJGKTStb8kuU/PeVg8dzqFXPUC97zV0B4b410/qyFc8FHM
         DUCLVHZuFTJChZQdR1uSIprM0vXL770BreTDoOBWM38sdoxD8AlZ9MQ2t1zI9k4Enqgd
         7+KfBi5ve1Whgc7DRSIYBhdRWphZSaylZ1mYbSPyCLDr9HQV2ycroUppORGzpP/8jUxr
         XxcA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=E7Jjj7c4;
       spf=pass (google.com: domain of 39lhwzqykcskxzwjsglttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=39lHWZQYKCSkXZWJSGLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id pf8-20020a0568717b0800b0021f2da568b3si340275oac.5.2024.02.21.11.41.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:43 -0800 (PST)
Received-SPF: pass (google.com: domain of 39lhwzqykcskxzwjsglttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-607a628209eso127389087b3.3
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:43 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWLjj//qAg5EF+soZo0hVHDEd9dcVf0boFOvBhsKExA6SGrZQLBiLFuLyNzlo0GJG0nJFaOuRAmg8ocEnnxf3+56PiG7tjxExtYDA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a0d:e611:0:b0:607:9268:6665 with SMTP id
 p17-20020a0de611000000b0060792686665mr4677003ywe.10.1708544502298; Wed, 21
 Feb 2024 11:41:42 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:34 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-22-surenb@google.com>
Subject: [PATCH v4 21/36] lib: add codetag reference into slabobj_ext
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
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=E7Jjj7c4;       spf=pass
 (google.com: domain of 39lhwzqykcskxzwjsglttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=39lHWZQYKCSkXZWJSGLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--surenb.bounces.google.com;
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

To store code tag for every slab object, a codetag reference is embedded
into slabobj_ext when CONFIG_MEM_ALLOC_PROFILING=y.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 include/linux/memcontrol.h | 5 +++++
 lib/Kconfig.debug          | 1 +
 2 files changed, 6 insertions(+)

diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
index f3584e98b640..2b010316016c 100644
--- a/include/linux/memcontrol.h
+++ b/include/linux/memcontrol.h
@@ -1653,7 +1653,12 @@ unsigned long mem_cgroup_soft_limit_reclaim(pg_data_t *pgdat, int order,
  * if MEMCG_DATA_OBJEXTS is set.
  */
 struct slabobj_ext {
+#ifdef CONFIG_MEMCG_KMEM
 	struct obj_cgroup *objcg;
+#endif
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	union codetag_ref ref;
+#endif
 } __aligned(8);
 
 static inline void __inc_lruvec_kmem_state(void *p, enum node_stat_item idx)
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 7bbdb0ddb011..9ecfcdb54417 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -979,6 +979,7 @@ config MEM_ALLOC_PROFILING
 	depends on !DEBUG_FORCE_WEAK_PER_CPU
 	select CODE_TAGGING
 	select PAGE_EXTENSION
+	select SLAB_OBJ_EXT
 	help
 	  Track allocation source code and record total allocation size
 	  initiated at that code location. The mechanism can be used to track
-- 
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-22-surenb%40google.com.
