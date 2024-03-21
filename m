Return-Path: <kasan-dev+bncBC7OD3FKWUERBPWE6GXQMGQE4PKCHRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 76453885D9C
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:19 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-dc6dbdcfd39sf2285072276.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039038; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZT5Lj2lgPe3/3objjEth3j8j8Da3fcV0aSEF8tdIuSQxjwGpZDflV4xtIA/hGNt5cG
         uwOuAGQS4grHduM5KHK2paDtMf78qs79QZgnyuc4Wlct2GuwxHdQiXbQzMKJ40gQXfJ3
         6+2roYj2XCeC3MaWkG1uSiNPnQBnAh49apMoTdRgtiLPQhFqbJH2Ej7JSLZD1FPQ46Am
         tHjAFtE88Fq2X3DDxX7xWt3giikXn5ZhoxNfbOoQ8wWKmmeTVwHqjS0qds7Oc1MMZVVE
         gz31Rsfe+RNPuIQQNtC9rRT/o0whsoKc1AoAfa0f7aWzbv+as7XtHJzxvfeIan2Ar+gm
         G6tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=AT/ihqfu1dvl1m8wgqCYNFnaHgaPTJ74DFCKaFCJPGE=;
        fh=kPzC2QGJHNLDEp+97Zm4h3JKm7LxHlpfmggdF41cMfo=;
        b=E1ec8KGlmCIOHgj9QiKVabZnGcuWgj4KNqwPRk3MrgNwy1cYwYLDBmFqsnbPltdvjv
         G5VS5mzd9g9iQW7ItnGM3mYc1gxze58C/jsF+3KRYUCejXtvuI+204eLjSXEuICVSYyj
         Bs81DBi+x7kQrrfuUR8y0OrAZXKlkT9ZRKEyqc7w8viSvjacGHibNAn+VNLvSKABVmtj
         55+wsn+FXwTMw5SsQFcnspA1GP/TaCnGGQyI7kMW5DfcSHluvBCVftXxWvzg5nOTEW3m
         KWV5fdvH8XmFctQByxhzwcKVTnqA6DKdjFRZnQTLyf14rBu14j3jaFI1FD9Rrnym8fH8
         TTcw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="0W/TqjOS";
       spf=pass (google.com: domain of 3pgl8zqykcskxzwjsglttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3PGL8ZQYKCSkXZWJSGLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039038; x=1711643838; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=AT/ihqfu1dvl1m8wgqCYNFnaHgaPTJ74DFCKaFCJPGE=;
        b=Gj+pwc7zrxpnNH9UcLc+XCMCsEXICm8DpmC+gL5uUZwaSkYSB39zOzdpmGgnU1yaMO
         cr0UO937N+WdsVjgudGmUpoRs526Q92wmgRp07gxCbX3mZWcS4/aKwGUldBsG2zuGIFw
         3kwbCl/fY2WryvqcLx72gywXw9yolihh5zisn18N5D0EOxwXIqUI5fImSyQ/vNwjh6si
         cQM+0KWzI3+T9IJ8A7trY+XP26sWkCo+8kYjq93ze2VDsuXxjbhp0Gem0mvt74I8wuet
         ZuKoUYseOYKuETExZ/S9YgviSI7kcBf8V2xD9ChJPJTuLhFYJ6izsV5co9nkxLanjt35
         CyHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039038; x=1711643838;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AT/ihqfu1dvl1m8wgqCYNFnaHgaPTJ74DFCKaFCJPGE=;
        b=Zcvf+XsjM4cI3VIinKsEulPqajWjPNgQeX4ID11lKQJQ/Q1yZcY5YV14ZYO69qg+oA
         ABMvVjQknuPzeak9BCRtGL8CJRCPfRVCCdjFLJKQiYddzKA/SokhmYJ8JrKvNApqn+97
         jn+dBu7khii6rZaONTsgyw60Vx6sibf38MCtYenVjzaXgNq5klt3hmA6F4U1W6V51d2N
         hH9aLSfqT9iEf4CnN4T1yjAiLqhnuar6Q6rKA4DNJ46KMSGc6BqIBOqqJKupgyr8bd1e
         NrMBUqXc1eMUJQayee2HptO9YuTOmI0xg0wOiugB1/eynwiw6eCVpIvcnreL7Aj3ntF/
         fc9w==
X-Forwarded-Encrypted: i=2; AJvYcCVPVcrtc6eL226NM1i44ALexvtW2xoNRPrshjccueVevGUcCLHiH573uLOTHUe88lEKHt4qoWMX37eylQPA3rvh7kT9DqHRAw==
X-Gm-Message-State: AOJu0YwyWub+r2HlqRfFya7z8SwSn615udVQHEf4jkoWgV9OvAqk7ubb
	YUIU60n1esqiFMJvlMeipfYFbzDHZfA3v/c4dOXNxads9fMsV9mj
X-Google-Smtp-Source: AGHT+IHYGo7b9hqQTtazvCTu0DFhmNSLzirWxQflTAlNzJeQNMsoSow7YNUUAxYv7t7qqWnWOhQq2Q==
X-Received: by 2002:a05:6902:230a:b0:dca:e4fd:b6d5 with SMTP id do10-20020a056902230a00b00dcae4fdb6d5mr2483357ybb.27.1711039038089;
        Thu, 21 Mar 2024 09:37:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:df82:0:b0:dcd:202d:6be7 with SMTP id w124-20020a25df82000000b00dcd202d6be7ls402604ybg.0.-pod-prod-05-us;
 Thu, 21 Mar 2024 09:37:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXU2VxJ7gVg7YdAHx3bgeHgpgEj6yIkT9a+Xt47Prep56XPxKIdkci+PYrBa4MDrT6CUpR98fcoaRqDVgZ17NiioyW4IZxSfkIcoA==
X-Received: by 2002:a25:bc8a:0:b0:dcd:98bd:7cc8 with SMTP id e10-20020a25bc8a000000b00dcd98bd7cc8mr2228461ybk.48.1711039037142;
        Thu, 21 Mar 2024 09:37:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039037; cv=none;
        d=google.com; s=arc-20160816;
        b=aDvvdflFCg2YfEfqw5thTE3AamBv/8jSvjoigzIIrmQEPNnAu6377GvrpcB0YuX8uQ
         Wz1BEJw9nhuhLh3uip94rY9iQUOlCO6TzZ2449YUcl2T2K/78FsX556qti85AUBoMQ0p
         Tof01OPl8vaGQrw3A9ULJoU3iOvNd4r1VzQsc1AhYCRVYV0mIJ/JBLbjTyyBT1qM6zyD
         YGitciGj6/HEfFJ6dXBZbXp7CJ0ss34rgEJMRNVc26PhT2s5/7T8ihEfLMbRU4Hu9qBB
         FeBdFokhrH64VI0Gn9h/7HkA0XWiMK1pOcqoMKcoUJi9i65vnA4o/R3OHd0rfPH6Hbv2
         QR6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=cRKfaiB6dOVHxpZUYVy57amQHTHiIgtHPVa28h/bxKY=;
        fh=95ZKZQoLgqWXjoAJZ5EwAwkXJP9m1EN8n74mS3ZkdhI=;
        b=FEyduMiFgc46nessqsVKBwEAX3U087goJwBqAyU2EXvfvLrHHXyMSzW/JvD893q8g1
         Eh/kOSW5nE/ALGhnt8wdJRhXr8DloYbwahGQu6Mm6lVNMjnBJrNq1g5hmjTB/gZGysVP
         beLYmaezGgHFeOtA1WBFLXgEBq5PGIQEDw9r6QfRIOjES2yyA+LklcbuY8iLwsaaEp3a
         rjdu7t9co9qfxozPuwk7vSw97yC8Eug3BPKXKVZPfIApT5Tkg0aNDReq3E9IlAIgGuag
         HA3lsOZk2aq8QZjkjcvMmd8h6X/OArjPJgxrMtifnhzK6gRGDbtiZHQKz5qq69HJYWcB
         7bvA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="0W/TqjOS";
       spf=pass (google.com: domain of 3pgl8zqykcskxzwjsglttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3PGL8ZQYKCSkXZWJSGLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id v13-20020a25ab8d000000b00dcc3d9efcb7si1723732ybi.3.2024.03.21.09.37.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pgl8zqykcskxzwjsglttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-60a54004e9fso21446217b3.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWSmjqj6mziU1lW97N3D2VNdPpzHf3LDIWSldRIJ58jeLRSh4n3hYKG8MS46mN2GR5F4cacESF7yLKaQOR+cQA2zXK5dXqcw5OcCw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:690c:f88:b0:610:f11e:9d24 with SMTP id
 df8-20020a05690c0f8800b00610f11e9d24mr1686171ywb.4.1711039036599; Thu, 21 Mar
 2024 09:37:16 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:25 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-4-surenb@google.com>
Subject: [PATCH v6 03/37] mm/slub: Mark slab_free_freelist_hook() __always_inline
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
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="0W/TqjOS";       spf=pass
 (google.com: domain of 3pgl8zqykcskxzwjsglttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3PGL8ZQYKCSkXZWJSGLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--surenb.bounces.google.com;
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

It seems we need to be more forceful with the compiler on this one.
This is done for performance reasons only.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>
Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 1bb2a93cf7b6..bc9f40889834 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2106,9 +2106,9 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
 	return !kasan_slab_free(s, x, init);
 }
 
-static inline bool slab_free_freelist_hook(struct kmem_cache *s,
-					   void **head, void **tail,
-					   int *cnt)
+static __fastpath_inline
+bool slab_free_freelist_hook(struct kmem_cache *s, void **head, void **tail,
+			     int *cnt)
 {
 
 	void *object;
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-4-surenb%40google.com.
