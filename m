Return-Path: <kasan-dev+bncBC7OD3FKWUERBUFD3GXAMGQEXPSLWCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0977F85E76B
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:06 +0100 (CET)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-21ea3c5425csf3087105fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544465; cv=pass;
        d=google.com; s=arc-20160816;
        b=006/j71UivnqyuXxlQnPiSYx7Swia5XZv6GFiCxG+8R8E+wepfR24QF1c4M83oDDdi
         UpA0Y+Umw5FXw6ufILzN2YWBr3GIx/Igp0WX4kzE/C4m6M0D9fj6RVLDssQYCXrnIhCP
         F9vUhh5EC2ksCsfk+Vi07mv9g/DMKnUFssowuFFZkSL7jUtIp1kz+yUPkjyjzBrNbi+4
         hXvHdGMyYRBq8v38iW4a1+3QerZ0dNiRyV3ldqinm09WyJxCorMc/bk0y1JV/io19bbz
         HDH5bNKMnaPtsIKRKlXMLCV1wlMsPQaqYr2vTmDbRQGd696VEAzpruiKJjhR8gi3oAvq
         3M3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=raKeuP+AtB6GR6j4W8L/wBL0Hbk1nQUz5EFRihLDjnE=;
        fh=HJ+09vAI891/xHHiQXmckZ2YV3DDIbv8TKkYh9qmTr4=;
        b=vQWrMTNYL6/+kC46q71yw+ZvtGIDWaiT3cfyg6fqhgDV/6HAhd5B/P45oum/qoMFVs
         IRWwZjIEptBsojRHF4xPZW59yi4uZeWfrI7IDCqw3gLRC5yU3qRWWzo7HFGmj/fAoCO+
         xyq8D9fc/S9WVt4SMsc02Dk96wqMi1bPvfFaKTNIOf3A4VGqJ+Hx1lhEB8n4diIbailu
         aQ7W3OOhhHjq6iRPOA6ZCjAAK/oBGyBKMf5aPKDYLcaAicjAGOPhGI7Aj57ySEpQ25cp
         Qc7mEDEeaSJom5hnjL6p1yiJvZiFp3Cw2iLaHb00Rp4TJzSHtahPrV0hRDn84+1vrDsq
         StCA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nE2rJZhc;
       spf=pass (google.com: domain of 3z1hwzqykcqiuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3z1HWZQYKCQIuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544465; x=1709149265; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=raKeuP+AtB6GR6j4W8L/wBL0Hbk1nQUz5EFRihLDjnE=;
        b=wn2Z9MkLECqwPunOO0TOY4nCLSEc4aUamUFRl2bYUCMP9PKoUonNz+7J26WcUpH58l
         Q+wkhlsz2gs2yRP4wqS8ZhOkLy1KpBorUTHeYx/HjyBMNEcHHIZUlCRp03+lu0GwFwHY
         aBRTqJIBknVFimLuvdP7N6IiBHJJ3hzEdSwV+UY0pPEIsgV2P+DO/7wY0bY3Z3FswHpj
         KE/SgbITNVtRZTY2HJrQ4rRLZTuklVydR5ELVBEqQfBlx1a+XwjH4lNgDrsAirsScjwq
         BLH5sKI/kgNauCIgRvEkiQ0j0IYl3+lbjCNEWUF/dZJqeOqHxa7xCi1jF130iMOqCFLt
         EyQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544465; x=1709149265;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=raKeuP+AtB6GR6j4W8L/wBL0Hbk1nQUz5EFRihLDjnE=;
        b=sS6WcIceMJHWan78RldRn3vLJKLZkU1MYaUKIJUe7nio35KAr5vOzI8dLOcRbOaLER
         fZBfghkxT3AA+QvYKCPMgcGaDMRFNuCqCVkMP2SkYCfPLLlondY5zPRrUg4HD3HAX10R
         eJ3xbqFQ/px2xkicIzenDia8wVvQpkHKBVtbtwejX1EnE/hLx/ZwjetnIDSogoDLYG0y
         p65N0yGysNxVloPOcCb4bzHSKmmFs1D2X0/Kju0Mqc9recKqD5kYP84DQ+qQEICisaEK
         exlyPIH70P3m9WOMpkrJASF3X5/VZTrbkdMTiqNCQQh1AaUbbmswjMNKYsVq3Gv8YjIA
         ryqg==
X-Forwarded-Encrypted: i=2; AJvYcCV9Ey4Bgd7786VENFfGTZQdWl+1+mf5lyhi9d3iFBFXmTUW3HPyCkvm8XqnJBLSG106+vpSbiSolbyeMz/pX3IDOkBv96RO6g==
X-Gm-Message-State: AOJu0YxU//tv0+WC6+ieQjFq+gKMCyhi9SaB3r07Akmt1+pryBX5VIej
	xCheVmg8Dk67W+8WGZq/xnH8oCwgkzcC6CG8QKlHbOJxSpoZ9f4r
X-Google-Smtp-Source: AGHT+IEQnAYNFLNelGi90kSENz4jd6aGSPqAOYIteoow4lUm2aG1MmfTQOe15Nh98otADz5drKFToA==
X-Received: by 2002:a05:6870:15c7:b0:21e:6672:a469 with SMTP id k7-20020a05687015c700b0021e6672a469mr15547457oad.44.1708544464832;
        Wed, 21 Feb 2024 11:41:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:612a:b0:21d:fc78:1e9a with SMTP id
 s42-20020a056870612a00b0021dfc781e9als1702155oae.0.-pod-prod-01-us; Wed, 21
 Feb 2024 11:41:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVkjFrmmpoyth8lMG+Qpc/v6oMy4rfJ34yzLSob7pgZ6Sa+R76UcNU39JV84z/iopFmHPQhrnz9MTdWgiq9lkVVwqa1Qy/TLjCO5A==
X-Received: by 2002:a05:6870:e99d:b0:218:51de:95e8 with SMTP id r29-20020a056870e99d00b0021851de95e8mr19370412oao.14.1708544463775;
        Wed, 21 Feb 2024 11:41:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544463; cv=none;
        d=google.com; s=arc-20160816;
        b=m3E4u9DUDCsMzEG/kk2ERY9ujJoC3u6LRMWkOaDi/3ksZtnMQjgfuNffW1IWUupRqP
         Qpk2NYghfdurFxTL+ebiijgw+X6ZP3RPT/xK1RfAPJ7PczwkEGIXNTrjklEj4nm4rf/r
         TsI1vGX+Uo/2V9T2GY6INPeTHxdnDiv4EmS6eMyifsCVtu+RVgOmfegUOKZA+hJuYw/u
         VOgSBTfsqp5UrM/T+mFjZM8/f1fs3k2Ffjr0ZUzywFdI2HXx3UZcOuy2COcO3eLOPErC
         YfvVUBmnckmPNiESAZcFQjGPFtpb6wnYncN0c/S/ApDnVioeFSXWzeQBd8cOfAkPbn7V
         t7Ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=aDZXV5wClyo81E7oQNbL7t5gFNRFpKZi8JXsyoMDgnM=;
        fh=Z7fTH9EDOMPbRgascKRjmk9yA9UxfNLHlLDhPDnVykY=;
        b=k9OPEzWGqf6X7Sw6XMfITE6kwBkHCmC8uRpUInoWeo5OSnWKJtOwnqZFF2pOKVWUu9
         Owq/yPjM/EOPc0OTPt99z78RIb6vBd8FHzWbAbbnSU76vUQ7bVmJDCVZxQpT9APn81v3
         KOwX5PMLaMxtB6VSuM8naA0SQ5BeOYddQnzmXoujSajQgphhovjT+mERtXSGdWrB+nXR
         tTYESPgfoewq7fqY1RfKesCL663gLppeqME7CBLMPoxtJ9G9J0gLPHPbE634OPXewYmi
         RiYkP3S+KXMbhKrBd6AQBcv+u/cjG2SHNhK8uQOWp5rTT1X/Pg7DgGG5t9+XGTbqr3pG
         6oGw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nE2rJZhc;
       spf=pass (google.com: domain of 3z1hwzqykcqiuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3z1HWZQYKCQIuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id gv5-20020a056870aa0500b0021eacde2bfesi682832oab.0.2024.02.21.11.41.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:03 -0800 (PST)
Received-SPF: pass (google.com: domain of 3z1hwzqykcqiuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-60895686ddbso3456597b3.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:03 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWCvBHY30uKqEDj4qR07NaDnyuMuqbTuxcXDxECPASDYdYhFrlWwqAF2qEvqlmkeQtW5bJY3jogfgBjY6GlIYZhK0Qdm8tVYREkzw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a05:6902:1008:b0:dc6:d9eb:6422 with SMTP id
 w8-20020a056902100800b00dc6d9eb6422mr17397ybt.10.1708544463028; Wed, 21 Feb
 2024 11:41:03 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:16 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-4-surenb@google.com>
Subject: [PATCH v4 03/36] mm/slub: Mark slab_free_freelist_hook() __always_inline
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
 header.i=@google.com header.s=20230601 header.b=nE2rJZhc;       spf=pass
 (google.com: domain of 3z1hwzqykcqiuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3z1HWZQYKCQIuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com;
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
---
 mm/slub.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/slub.c b/mm/slub.c
index 2ef88bbf56a3..d31b03a8d9d5 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2121,7 +2121,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
 	return !kasan_slab_free(s, x, init);
 }
 
-static inline bool slab_free_freelist_hook(struct kmem_cache *s,
+static __always_inline bool slab_free_freelist_hook(struct kmem_cache *s,
 					   void **head, void **tail,
 					   int *cnt)
 {
-- 
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-4-surenb%40google.com.
