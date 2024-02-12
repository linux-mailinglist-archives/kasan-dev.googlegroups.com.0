Return-Path: <kasan-dev+bncBC7OD3FKWUERBIVAVKXAMGQESNQYV7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DB1A851FC5
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:39:48 +0100 (CET)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-602dae507casf63579187b3.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:39:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707773987; cv=pass;
        d=google.com; s=arc-20160816;
        b=bFROY1vcxh90Zcob/L3BuGsDYDpDTqKgQRO+SqxXYgkoJVRs029TtvHoVTOUid49gh
         iieDIWQSnHWx+jEV5uHaM6KmcjuSKAYjyEz/rr/ajhAim8OkBSJXnAiVjYsvsJg2bZTz
         iKE9MpaWoO6Og3Jr89Ib8MgjAw+dAv1rUSmHdKuSq4pV9McIeHu5RkSiMsJbEaFfje5K
         5Zf3+spKnyr0Q9nvYrt4xWFl5Ohnxb0jeNjLJsQ9i5nF14zqBWFfPbKJ0dNxyd+ZkL2h
         bT+7847andqCMoT2GF8zu0q66Hrs5yVZ8ggDgN8zBWGE0NJRoGM9fFvPECiS5szk2Y02
         MOcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=G7eadAt8w1J74d2rbKGRKuz3b2vpLsJ9puUm4QecxGE=;
        fh=18/DNfvfaiomi/Mcbbx9D6+tauZgfU4LprMrkYdeizo=;
        b=YzY4NpZdoeJXdwhydlNyVXDTXQo7/VV1+R795+tHofFg8XCCpqvlyz6BTWIz5bv0ss
         NmTRxyUUr1S61OgOWcM3AFWCQp3oNx6Wn2rgiygN/4/3+aCKtOZvXB+mTsbSp3KGZlVW
         P/QMlCNxhtO3HmZNsNy2djFDEoRRHeTHu8oD+P+UL4+JWY7eBk7dt2XGB2uDgpXLf4XI
         TwBWk099chhiIQtceL3dloQv8xdG4tJP+spJcXfGlEJf/cVIw7C1XMsIghzglG/xB8og
         EBsP+6Kb2DpJZ7z6R2UUPsz8LU8hFwNpkis2vF7KVsBkzJPKc5etI6x7dhYh3wWY6jER
         q1Nw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TQVQzCxi;
       spf=pass (google.com: domain of 3izdkzqykcaasurenbgoogle.comkasan-devgooglegroups.com@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3IZDKZQYKCaASURENBGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707773987; x=1708378787; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=G7eadAt8w1J74d2rbKGRKuz3b2vpLsJ9puUm4QecxGE=;
        b=SLHoANZfYFOh7s5bMZPrX65eoxv+nl8DxKtlPxUIC/NotYSrd3fU5OfDIQnG9D9hmB
         Q4RuydYeVGkoEPNipk/Ib41/JLEiJ3+60EhBhpXzE5+VurjKoWx6xMOrtooRYfw4XPf8
         Q5Hx34CXB474j3eDc5D7nNVA5Kh/Ajca+Ip8VOHzAe/5hX6z+BROU0Z/w9w9Aqhq+lNn
         2kyyNDZOS2rAzQGY1BgH3D3bMRAMYlwhSh3OTdIdr8EPPErGk3loi8xQkUizmJfLvW34
         wZKINHvXUtsjk0HszqHruJExHj15p12syr/WcyN+PQs6SdmcERFs6TFVa/BZFgOzeH7j
         l9PA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707773987; x=1708378787;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=G7eadAt8w1J74d2rbKGRKuz3b2vpLsJ9puUm4QecxGE=;
        b=E8ju1T++2XZj8SGAGX8yZV1hRdWetG2hXUYXM+fs/GdJoxcza7/IrLm7GftN5b4j+B
         YRg3sLqCz4n1cGCBYYxy81+Cr9V7An6LFq1qjEEBbdUC+pPXNhvIMDL+xizBH1UYikyO
         tKbW2mdnTiM2+EvWLbr9MLZpkPdrV6gp4G5zreOuXAEJshfwn5K4plHFxuvz1coi9rEf
         dwT+7ZYh92cvg6wulvRRY7CNZwrzuuBak7um/7MsBuJpZmVNauFf7yWD6yypr4urdp2f
         hpNJj3sWd+HyqHBa6DWp1qeo+NjczQOF8jY6LDGeGvABuAdNh46mbUSdTPw+HEzgBcXI
         Bf7g==
X-Gm-Message-State: AOJu0Yzny+fbksivqbV1QrqNlboj8TWiLhB+2YcqI1AC7cOSw/KDqFVK
	H8Of3vNElhCCKRENy4YJsAsXxNP9TTmbzbi2aVl8bjJb1z55ltqu
X-Google-Smtp-Source: AGHT+IHbvGlCiG0RzNZJc0h3lGe98mElk7TqTvZdrQ1e//ukF470Ul6xr+7nKapEv0GHlVcKyDrssQ==
X-Received: by 2002:a5b:47:0:b0:dc7:4854:1b1e with SMTP id e7-20020a5b0047000000b00dc748541b1emr5532332ybp.54.1707773986876;
        Mon, 12 Feb 2024 13:39:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:dc7:b0:68d:97d:785b with SMTP id
 7-20020a0562140dc700b0068d097d785bls989713qvt.1.-pod-prod-08-us; Mon, 12 Feb
 2024 13:39:46 -0800 (PST)
X-Received: by 2002:a67:cf8c:0:b0:46e:c4d1:25b5 with SMTP id g12-20020a67cf8c000000b0046ec4d125b5mr2008337vsm.22.1707773985850;
        Mon, 12 Feb 2024 13:39:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707773985; cv=none;
        d=google.com; s=arc-20160816;
        b=EtdEizA/NYhDGy9v9CJ7ngUmaGwM/f8hQ1kfTQ6jlzAnnPFN+I2iHExCN/rdeN9DPr
         yGnpkyUhgk7h+2Ea4rXtOhnN1j+Iooe36i4C6UMLG1kZxUHblsNu4lfYb/55LIIYuB1b
         edenviEwhsj4yv0BdRgWi/loHUp2WKzKHWMENmvPG8xo1sN06KK+yYsJfy5+uAjdJImV
         fXZDruAIiYTk0+raGVWbpeb9AD/LgklfkYm5TKmRj2zlfkfqQGfAidzRGTO/1IxQ/lY6
         uFxiPqmvqIq+0F4bzt4XuL1HWaVUD1i9Viyk06nGU7sc9x4TL5OmB4q+awMGk6700r+o
         XXoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=NFEoAydGNCIakLM+oYHcpcvSKcGKjy30qzf4+mOY1ag=;
        fh=18/DNfvfaiomi/Mcbbx9D6+tauZgfU4LprMrkYdeizo=;
        b=pQb+tTgYXGoZLQiDeMy/uKkUwyt1B43DHtuFnvBEC9ieVOodkyTkYWNjko27a75eOE
         riXcIleCm5Niry3ecOWChzhrwt6SrrmCBe3WE7PiKn0B5uLRgCyZKUz/DJ48hMs/Cz3i
         YYyI47EW05WQNVYEXowZf2Zq4Eh+HLdul898bWvZi7XM3If3JlLwD29Ml8uAtbw1135g
         R/IQHLAxqsaWgx5CmDVEqme4nlqXwosZDp9tLLF9tSiwa7OQzPf5GszheRneYR099NbS
         RPEh6MBkbaGs4k7+fgC4pJZhbelL03dvXWgA2OrHa3TFCQRgFuLutCaTwOiWhbHNnUqF
         S64w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TQVQzCxi;
       spf=pass (google.com: domain of 3izdkzqykcaasurenbgoogle.comkasan-devgooglegroups.com@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3IZDKZQYKCaASURENBGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCUCWkjk7mo8+3KYg2TZnKVonpn3R8D52OFiReDI+gwBAhLkF+9zO49hLZdcTzYHm8Yz2Y5oGrkxA0ihctEI8sb5usFKfh3T6fwcgQ==
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id k6-20020ab07146000000b007d6e93f4d42si509071uao.0.2024.02.12.13.39.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:39:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3izdkzqykcaasurenbgoogle.comkasan-devgooglegroups.com@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-60665b5fabcso4470517b3.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:39:45 -0800 (PST)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a81:a003:0:b0:607:8294:7631 with SMTP id
 x3-20020a81a003000000b0060782947631mr42744ywg.10.1707773985395; Mon, 12 Feb
 2024 13:39:45 -0800 (PST)
Date: Mon, 12 Feb 2024 13:38:52 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-7-surenb@google.com>
Subject: [PATCH v3 06/35] mm: introduce __GFP_NO_OBJ_EXT flag to selectively
 prevent slabobj_ext creation
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
 header.i=@google.com header.s=20230601 header.b=TQVQzCxi;       spf=pass
 (google.com: domain of 3izdkzqykcaasurenbgoogle.comkasan-devgooglegroups.com@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3IZDKZQYKCaASURENBGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--surenb.bounces.google.com;
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

Introduce __GFP_NO_OBJ_EXT flag in order to prevent recursive allocations
when allocating slabobj_ext on a slab.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/gfp_types.h | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
index 868c8fb1bbc1..e36e168d8cfd 100644
--- a/include/linux/gfp_types.h
+++ b/include/linux/gfp_types.h
@@ -52,6 +52,9 @@ enum {
 #endif
 #ifdef CONFIG_LOCKDEP
 	___GFP_NOLOCKDEP_BIT,
+#endif
+#ifdef CONFIG_SLAB_OBJ_EXT
+	___GFP_NO_OBJ_EXT_BIT,
 #endif
 	___GFP_LAST_BIT
 };
@@ -93,6 +96,11 @@ enum {
 #else
 #define ___GFP_NOLOCKDEP	0
 #endif
+#ifdef CONFIG_SLAB_OBJ_EXT
+#define ___GFP_NO_OBJ_EXT       BIT(___GFP_NO_OBJ_EXT_BIT)
+#else
+#define ___GFP_NO_OBJ_EXT       0
+#endif
 
 /*
  * Physical address zone modifiers (see linux/mmzone.h - low four bits)
@@ -133,12 +141,15 @@ enum {
  * node with no fallbacks or placement policy enforcements.
  *
  * %__GFP_ACCOUNT causes the allocation to be accounted to kmemcg.
+ *
+ * %__GFP_NO_OBJ_EXT causes slab allocation to have no object extension.
  */
 #define __GFP_RECLAIMABLE ((__force gfp_t)___GFP_RECLAIMABLE)
 #define __GFP_WRITE	((__force gfp_t)___GFP_WRITE)
 #define __GFP_HARDWALL   ((__force gfp_t)___GFP_HARDWALL)
 #define __GFP_THISNODE	((__force gfp_t)___GFP_THISNODE)
 #define __GFP_ACCOUNT	((__force gfp_t)___GFP_ACCOUNT)
+#define __GFP_NO_OBJ_EXT   ((__force gfp_t)___GFP_NO_OBJ_EXT)
 
 /**
  * DOC: Watermark modifiers
-- 
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-7-surenb%40google.com.
