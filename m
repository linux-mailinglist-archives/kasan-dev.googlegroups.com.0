Return-Path: <kasan-dev+bncBC7OD3FKWUERBWEV36UQMGQEUWXM6UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 1461F7D5236
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:06 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-41cd5077ffesf1509831cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155225; cv=pass;
        d=google.com; s=arc-20160816;
        b=dHPncWqhMq+5/3NryBGqLlcJNgBkXUzGLN+cvs0is45WjtYfERs6cmFZ3R6aZuVvnG
         8obAnh3/oH2ZWtq1ZyfWRFe0MbVAZ8oflUIcak+VI7QfRn0A4NC+WRm6lr0jD4jQOobt
         h7JOfFP2EBMEHDZTtAwUP82HDvpb02by9pkVulIfqV7z/nFD4tnZ/ZIETcJeE9iK5TaH
         vsPwuru3ohCY8shXJITmnh02xou/FPC5D4J9H6VrpOa6Z0CMqI0+zQR/XyqlAgeRg7oC
         jLJWznR683GVFXmBc338ma/+97bIQZgJxjZjn4nWRLJezLXssm6oE/dW2pRGfcJH580v
         /M+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=uc7L3EJLpHsNaqAknaLmmkpv3n71Ag3Izt34u3VPkNw=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=ailh33SqdU2MU+OCrHld+eV0rioTXoVKRJP9JTEqQUvFyXmyfe7cNeo1PYCmCj16kU
         Vi8vUFLqXLYUVEtdApQZP8n1Ff9TD8hHG1NHLixsgD2Z8xOVkiMEp/9+5xeu/Pw1IA5+
         ISgk3lerZWB1Q6vm5/95EAGOqFEWb1gqQq8cxaAiBHIL8z5Sj/g+ZQx5yXXkHNjp2wlH
         gnGEEBnu7+1B39mdWQirnlrGFl45D95MT258lGE+lMo67YQHegDdhTLKaR1UbyL3lo2v
         7phz0aSQZ+q4dquZoJG/jhe+Zp7VzlrxjPtRBT/hRZpccys2WbeAbFDnUZ/SyHSrEZQB
         cjOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="iW/7OQ+E";
       spf=pass (google.com: domain of 318o3zqykcxwxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=318o3ZQYKCXwxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155225; x=1698760025; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=uc7L3EJLpHsNaqAknaLmmkpv3n71Ag3Izt34u3VPkNw=;
        b=Yf+kdjUuK9WiyoKitM3w3Tp2PCb+shUXKgPm++zpOLlNAnJUVncfIQsOAnChuf/edB
         xC8aRtD38BtSJr7yTo5QxI3mEQsBMrfc55NX8Rka6YnrrOx/xZzZtkvB4pSAbqxKzkW/
         oPJH9Rz/LwU8k+ZU3d3Do1dhuHZBE4pbhF/DjioRhggn98aRsXjwYkVm9nVJxPwd/fp6
         lE9xwNOpS77sO/DhEbUjUsf8Qt/5WlvtECqVE+mhQ+ESpD4PJBJh7SecrMrZ71JtE7wP
         l89arVKlPUPkRfIDVUZvdtJ2GpqpEY1Ed6GlxDmJ0iAgvlNusNE4an/PRT40AF4XOuwI
         sHcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155225; x=1698760025;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uc7L3EJLpHsNaqAknaLmmkpv3n71Ag3Izt34u3VPkNw=;
        b=PPu8+ZtQonU4gy43Sb8DdZWR0o8rLXBAAPS586Y3LxwZ9HvbJ2S54GgDm6XUHUL/xS
         RqVtN7xUTjFy8RfKo/Z9MzhPuxvbTw0bYWlmxWVMo/hNVLfY1oVuSaghBjR7Y+fIL4Wf
         KOV90Mubw2fN1k9a4EERwlO2BsjdX5h5FDLUePBLTZrjuehkNdjCVjEwkJl/YQAzlTkT
         OoIyCQHbnCSJCYlknKLPRmPOxwy6tlsxOPXD2UdxJ4CCFzkpQkXB+r3n55erey11gV4M
         WIERU+qiXlV8vpgX+tH7u61vy8pasgqCZ4nxKy07vqbZvHsifZwptPnocXUtbQjpFB/e
         pb9A==
X-Gm-Message-State: AOJu0Yxl09s5iwe6yPpgtb1rc8m/qjx8yDknsU7yT2EUKBLBhHiDjP9j
	v16YMuEPrjXRMTs675Aa/Mg=
X-Google-Smtp-Source: AGHT+IH57ryn/xAENhBWtw7+KV93solPA3zPr8+bjaNTtpcNRobtmthVUQQgkFZE6I7tmL/lydWjJA==
X-Received: by 2002:ac8:777b:0:b0:417:944a:bcb2 with SMTP id h27-20020ac8777b000000b00417944abcb2mr195683qtu.13.1698155225094;
        Tue, 24 Oct 2023 06:47:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:57d7:b0:65d:b9b:f30f with SMTP id
 lw23-20020a05621457d700b0065d0b9bf30fls1146838qvb.0.-pod-prod-07-us; Tue, 24
 Oct 2023 06:47:04 -0700 (PDT)
X-Received: by 2002:a05:6122:1148:b0:49d:9916:5747 with SMTP id p8-20020a056122114800b0049d99165747mr10801252vko.13.1698155224418;
        Tue, 24 Oct 2023 06:47:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155224; cv=none;
        d=google.com; s=arc-20160816;
        b=G6XpHO3ybtSbAhOm4JQ4qIudd+L4urXAvjLncCO/jSd9QyT9ys3qD3ZMNIlAMGbK/I
         +U3QrnEgFC54zGxjrd16J9lTcu0vR7b+fyDE4QrFH3QIOXIG4at1diANkhIKgpMACsyM
         60ji5QH538SYFzKjbvfJj+hPtVRXFSf6e2HsZT7ajWlCiDXMkWOz/z1FbXPt4T5K7o8H
         iYHc7PMfYWrCy8b+b4WoKjC57sBxRz0s+tvERIWYFrsWkMXGaq53shWoDdTyPd/jc7kc
         NrwVrIGgePW+7neOx54J/OI0E8PElbYh+UEIpdbrX3GgWoPzs0P5cipQdnwTEPGDVXA+
         scLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=YHgfLVMScT5H/FxRnxJh+3xP9v/l17ghYQJMJklbWxc=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=VdcOEOftX5KNapHIaVlQxmBka/mzV9c6xGsKdJSGTFyrT29uHyyFpQRBuQP1A86Gy1
         32TN7j5R3iGII07NTbksarXdwfRObLljonAw2bEKFf+7q56l2RAcvfy65UeD5YqD4zmd
         YPNYtr6Fm6XotP1Yw6imbMq2/oHEKxr6mnuvDBPYzvLOgCNYyT+Srp8WjOJMmycj8E1B
         etxPNv615nDZ2cg9WsWpDYn9Y6lDnm1vEgS54q1ibLOt9F/aeLjtPrWO7z+VIdM1Nd56
         g7E+xV/9vTWC2K1neeCCQXgM7THMooGwZpiilYWkHs+KZdZztv9PixN/VLBN0f0QUZf/
         QLlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="iW/7OQ+E";
       spf=pass (google.com: domain of 318o3zqykcxwxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=318o3ZQYKCXwxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id ec14-20020a056122368e00b004937daab34esi367880vkb.4.2023.10.24.06.47.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 318o3zqykcxwxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-d86dac81f8fso5389042276.1
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:04 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a25:297:0:b0:d9a:4c45:cfd0 with SMTP id
 145-20020a250297000000b00d9a4c45cfd0mr213074ybc.2.1698155223878; Tue, 24 Oct
 2023 06:47:03 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:07 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-11-surenb@google.com>
Subject: [PATCH v2 10/39] mm: prevent slabobj_ext allocations for slabobj_ext
 and kmem_cache objects
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
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
 header.i=@google.com header.s=20230601 header.b="iW/7OQ+E";       spf=pass
 (google.com: domain of 318o3zqykcxwxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=318o3ZQYKCXwxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
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
 mm/slab.h        | 6 ++++++
 mm/slab_common.c | 2 ++
 2 files changed, 8 insertions(+)

diff --git a/mm/slab.h b/mm/slab.h
index 5a47125469f1..187acc593397 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -489,6 +489,12 @@ prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
 	if (!need_slab_obj_ext())
 		return NULL;
 
+	if (s->flags & SLAB_NO_OBJ_EXT)
+		return NULL;
+
+	if (flags & __GFP_NO_OBJ_EXT)
+		return NULL;
+
 	slab = virt_to_slab(p);
 	if (!slab_obj_exts(slab) &&
 	    WARN(alloc_slab_obj_exts(slab, s, flags, false),
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 2b42a9d2c11c..446f406d2703 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -222,6 +222,8 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 	void *vec;
 
 	gfp &= ~OBJCGS_CLEAR_MASK;
+	/* Prevent recursive extension vector allocation */
+	gfp |= __GFP_NO_OBJ_EXT;
 	vec = kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
 			   slab_nid(slab));
 	if (!vec)
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-11-surenb%40google.com.
