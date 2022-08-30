Return-Path: <kasan-dev+bncBC7OD3FKWUERBCMMXKMAMGQEWSCCEOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AE9E5A6F91
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:50:03 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id c27-20020a4a9c5b000000b0044df4a6e6f4sf3220717ook.15
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:50:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896202; cv=pass;
        d=google.com; s=arc-20160816;
        b=DQb+bVYuZLhQVff8z9ZmrbdSr5lPO+cnfRC51v8IXcEgf1xX2RZqDARjBFN1IK78Qf
         rMiCZLS80ISYqo5q5ihJZIbW5usWfY7x+MSiu2eMAmX6Xcc27vRieVlt/sN+EP5EQlmR
         Tu7f+lMj7nYxXhUMtpU+Hc+uyvf9FzJmKYbHg54P1wu4PddkhEKiQRj91KPfHW0nL8ZX
         SyZlVTf27raWxJZ+ojQN2qzatra98ZHml92Us5O8+qJuHXL5kDlBBNrFcDTzQHwUjWbt
         9UouIQoGseX8TNxpDCwfBCF72JyaUvPKiGbP9nYph/Rg+PDQ1M5QnfjGnt+ZsXomSIF0
         +pRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=C/FeSQfqfYphLVJrx7CMmHveS8eGrrL5Nwr1Sl0Gtgs=;
        b=QoVkqpuGJ+yCPa7MBhDoxFbpy4splBffeWBBTZVMcq4MFk04uqVCpbdyW51iZF/aEj
         xcSqeu4vCKJ503gJgdVjYFdGeazz9jtu1K+Kfn+VWWuHRGEMXfOGgFpb8kvqutgMXM8g
         mrtKsPJMwhrQgGGwyOYXXZDMyhch03YROfbFQwAqL9yri9Ke/BPpMT76M/LUlHrL8QCL
         1btWzZl1yY7EpCpvSVeW+v1DmaQos7cLwKgFafnzWBRRUzcV72r9MTqMM7lGO+jVUxXJ
         5L35zVB0muwGquIc9LdGrhS8PLbKiR3RLZGi/lfIBQf42akAyHusOMr1OUgreo4CoyFp
         38RA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pP4c3oP+;
       spf=pass (google.com: domain of 3ciyoywykcw0dfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3CIYOYwYKCW0dfcPYMRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=C/FeSQfqfYphLVJrx7CMmHveS8eGrrL5Nwr1Sl0Gtgs=;
        b=HNXtVEhUWDNMqRhUN/keWttNnTxjHGOWJ+f45ppAkkB6C9N7nbSGHOwDHBka07zzyZ
         grzmMv0oeQdRZAaOs6ICzV6zrMFQmlIqTRmhwU57/1dJDktVpXAqcpw1Ou3ptKV73jkO
         ovEibgJ7AeKNXrohUmxLQk97wgKgELC37XSkClcH7uzeIKF23o7zqGfYBOWbr/el8HT4
         lCioMfhWrhhdDmHVmQu6UIzqqPcaG0pYX23YFcqcleTmQRNg6I3uur1vdf4P0WWGwUoA
         9SetaVvXM9RO26eTohFEwxt1fHYLRsBF2SYK7y0X9wbj+6szAEVQmP7nSEjk/UbFt0LX
         nIvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=C/FeSQfqfYphLVJrx7CMmHveS8eGrrL5Nwr1Sl0Gtgs=;
        b=PHlpKuQzPAfjo/eEL7jlxQJ/mOkyrrRJpQSUyFFBtWEcQGb5PTY2UPokwdismtmyGt
         dfG/I8dfEcZdRXEAH3gnsqv2xqy6y8JSuEFf5R8IXIhoM6htznRmnrw0FGM+oSVeCEWO
         deS9MAj5adsT2oWPLh/4Z7aLBds+iNGZAfpFM/yO7DoFVqDDW1kRU9mbHrRjUpR0sonP
         Z8EE2YkQPG4uOiKX5pWSMctu/B9kVpgiViBgvhxNqMLr5lBt/qlX/H4m4Aea5hvIHkzb
         fbFTom1Zr2bar1XU+ET0qr8kEHj0pecF4RNv4LKfpCzyYHLlJQs2lXP1ADfVDZXrQTdH
         Hq3Q==
X-Gm-Message-State: ACgBeo2fA/HSKXmi9d4UkrncFla7bIrKq+AIRPeDZ6u1JoBMBoOrslpR
	DSNyB/PbjeAP1cFU/ty9kNk=
X-Google-Smtp-Source: AA6agR66kdbLpNv3rS7iN6wiggK6h4UHBhEZcXonbNwKc7Vv5j2JsgJEhxchB3v1HprbNZB5OHvp8w==
X-Received: by 2002:a05:6870:e2d3:b0:11f:3ac8:d150 with SMTP id w19-20020a056870e2d300b0011f3ac8d150mr22714oad.286.1661896202017;
        Tue, 30 Aug 2022 14:50:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:2292:b0:345:3674:8896 with SMTP id
 bo18-20020a056808229200b0034536748896ls3872262oib.2.-pod-prod-gmail; Tue, 30
 Aug 2022 14:50:01 -0700 (PDT)
X-Received: by 2002:a05:6808:148e:b0:343:77fc:b7d2 with SMTP id e14-20020a056808148e00b0034377fcb7d2mr30040oiw.128.1661896201253;
        Tue, 30 Aug 2022 14:50:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896201; cv=none;
        d=google.com; s=arc-20160816;
        b=CuiagSMXvlsBpTR+E1S2ArLL+SCHoiEfQ8XYqUt1+yooxletllVnOFF0I0HaTTRiA+
         JBxMwBBYE4D/7Buqm5lRY77EVqkI294h/s1CPmZJLFfErR0uPnsrdQJ+eJ3f+HpqJcRj
         WhfKBwlbIWh3TcraCoIYRGQqZhUoc0nPamfCT56+zOQiB8FkZCBWQv36NXvQfoqi460I
         sCWCjavNrUZpa/OtWmtGfJKmZGXQOtHcj+Q81cOMOoihbGq2H7eCpzcCgXYVylj4124B
         6/zprWx5hWb2p4lEkoiSZWUbqulndlNA9htkr9TggtPTN2mI9ZrmIa/DaQzL3NaMStKY
         qgDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=gY+PdoFf3bNnEB0W9Vd0woPoFdt9hhtegjhiPtTj+AE=;
        b=jqaK4ev4zlbEEdau9CWVU0sSTnYtruWMTxE8zBJ1Gy86ls5cNfbEcyxUcD6/rdxYM8
         pULvuMynj19WBfSgR5LepiJNTkkRYmAENreAZKEwPDYszpUxoml9y8TKwuJLBRPpCPVP
         qss6WAmWiFLjhJ8Z1PBpjeKo2EGgX92F9DmouCUMMvWQ0ZSN5jLZufHs1EP06ZWtNkcc
         h4zkY/RoQQuS3fozjw0qr2b8poHS0p1CaRSkAabxVVB7gdC/8+ZuejAal3Yo06YG3Q61
         uXDlJQ4K4Cq9pwmScwaMuEyb4tKnYjbzvRopur4VFnzbmY9WrqAGNqNgjd9GM9plq8Rt
         vH4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pP4c3oP+;
       spf=pass (google.com: domain of 3ciyoywykcw0dfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3CIYOYwYKCW0dfcPYMRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id z42-20020a056870462a00b0011c14eefa66si1291778oao.5.2022.08.30.14.50.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:50:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ciyoywykcw0dfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id d135-20020a25688d000000b0069578d248abso726443ybc.21
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:50:01 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a25:ba91:0:b0:683:ebc2:7114 with SMTP id
 s17-20020a25ba91000000b00683ebc27114mr13866830ybg.319.1661896200808; Tue, 30
 Aug 2022 14:50:00 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:49:03 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-15-surenb@google.com>
Subject: [RFC PATCH 14/30] mm: prevent slabobj_ext allocations for slabobj_ext
 and kmem_cache objects
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-mm@kvack.org, 
	iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=pP4c3oP+;       spf=pass
 (google.com: domain of 3ciyoywykcw0dfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3CIYOYwYKCW0dfcPYMRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--surenb.bounces.google.com;
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

Use __GFP_NO_OBJ_EXT to prevent recursions when allocating slabobj_ext
objects. Also prevent slabobj_ext allocations for kmem_cache objects.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 mm/memcontrol.c | 2 ++
 mm/slab.h       | 6 ++++++
 2 files changed, 8 insertions(+)

diff --git a/mm/memcontrol.c b/mm/memcontrol.c
index 3f407ef2f3f1..dabb451dc364 100644
--- a/mm/memcontrol.c
+++ b/mm/memcontrol.c
@@ -2809,6 +2809,8 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 	void *vec;
 
 	gfp &= ~OBJCGS_CLEAR_MASK;
+	/* Prevent recursive extension vector allocation */
+	gfp |= __GFP_NO_OBJ_EXT;
 	vec = kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
 			   slab_nid(slab));
 	if (!vec)
diff --git a/mm/slab.h b/mm/slab.h
index c767ce3f0fe2..d93b22b8bbe2 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -475,6 +475,12 @@ static inline void prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags,
 	if (is_kmem_only_obj_ext())
 		return;
 
+	if (s->flags & SLAB_NO_OBJ_EXT)
+		return;
+
+	if (flags & __GFP_NO_OBJ_EXT)
+		return;
+
 	slab = virt_to_slab(p);
 	if (!slab_obj_exts(slab))
 		WARN(alloc_slab_obj_exts(slab, s, flags, false),
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-15-surenb%40google.com.
