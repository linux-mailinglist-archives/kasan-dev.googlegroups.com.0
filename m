Return-Path: <kasan-dev+bncBC7OD3FKWUERB75D3GXAMGQEKS3LPYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 61B0D85E78F
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:52 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-42e16ec3492sf39189391cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544511; cv=pass;
        d=google.com; s=arc-20160816;
        b=tMixQy+qrhJ/bpGZrB573wpd3kyiqH72qIg9DWpbXjpFJejCokjWLk7nMhwFlIdVYr
         CEzZPgFUD1KlxUVRt9psiOOlQdmG6u4BU2Lft6G0T+Li40dJWaDAuQGTzXtAWjqTcj/0
         ntDRdcBH3OqQLHNKJR0SkQlM0voqwZmHPjLUtJhBawiivMfIHO5dkjLLDhLvKmLKKSAA
         XaEzqPmIQWImQTurturuq1LtXrkzw3NpjahAeY5gZrcUpqDaVLQmZ5hLH76adYPcvv74
         z4x2he9I1nkbOx/0ZrGV9osEG+v1LaFlxeJ20pt+vKIo8kANe+qDsGg4yT/GK79Xfgfc
         Rzdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=FCgXqj/QdJ1P3WwcDoJACggy5Pip34VO5fTi+80Y3AM=;
        fh=TGfTFiqGtIz6YT/XzIzXYxAWDs/Zjvz47Tfz/xiK+Dg=;
        b=Ml6rHoAXryHDeD5vwmo90m+srGGFolHCQ05js7aY4SMqOGeum4yyERribbmyxC1vUH
         i3su+5c0uoJ27VNiYBhrVz1PTPkrVBz5p5rd7sZkoUyDIFK8tiAAx9GyTtokxOrjO8Uv
         VHL8BHB2HoJgq1u93IYlfH7I+z7dlR6ByhMhA1MWKiZQ2wVB1sFm1xkKTdabSbRzlTLQ
         4wqWYBB201B66m8/lZUv+gLnWpnT8tmxjsMaatKcSKMmodqGI7JljzpQ+t9iEPDr3dhG
         c+4Qe3iCZWYrf1T1b6nL/Z6FGD+xGyphoVnk58FrSfCSFmkFR1P64qNnLYq81dkv3cb8
         nF6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kvwVPRBy;
       spf=pass (google.com: domain of 3_vhwzqykctaegdqznsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3_VHWZQYKCTAegdQZNSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544511; x=1709149311; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FCgXqj/QdJ1P3WwcDoJACggy5Pip34VO5fTi+80Y3AM=;
        b=Pt/tkFo5SOlmFRJIchq2Gl2oVIM6m60pGmkVOIPHuL1r6mscc6YliKj2yRnncw1a0v
         lnusgN4bP/WftjVVg+Kqsx8yDp4R9l0L2m6z6O7cFuj0iM+zKSzhoY7pgWpZKkspXg1F
         GHMHKsj8sJGvsOwEc+Y/3KAzqrHd56f3yE0RuYKpIkRcYRR1CZAyBmYwD/1b4pTYiZbU
         /NQcx72XjURBcXtohQnqWmv00AQj6T0Lm3+PjjcPRVAy8UmCPfQSroyo+JHOP5+LcdL9
         fGCXN5HTr7KhSb8rD4k0hEdtP4Jwa/iC41MC+ZNymJRe7GREq0UJx90613k8mnfcvIAs
         HfCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544511; x=1709149311;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=FCgXqj/QdJ1P3WwcDoJACggy5Pip34VO5fTi+80Y3AM=;
        b=MuBV7aG+zjCrr6Jy/NBh2m5f76X1saXTv3AlLicbsDpeNzENhlhgvoa+ViuIsQuzyI
         Rn9i6c7h+U1s6uWm9nK/odxE7V7s/T0xgcjYTJdwrCF5zRplXOZzSKwnDuGr+I20VbCZ
         pXiysr5sv95eoloVKnEdkN/tjIK3Hc+zFYJTSa2vdN4fiY6PWz8XhrLiWUJ8uC5L6lgQ
         epb4JD26kcT88s8a9zBV7nSNzrySasOQyEPQSlTWO8mSmV668zajJh+KZQUcl2Lmi5/v
         Evfe6t2PCMlnZ1t+ieZpr7BzhGdQLG4IlX9McXL88vP4Jn7xUDQ0hnNUopRUFBt2t65u
         juGA==
X-Forwarded-Encrypted: i=2; AJvYcCXEk2NJq0vevxi14WMFuPP9bBiQlWg0SrV0AZ8d0vYoJaqQQglGTodmO5jzw6kLfFy/A+eAZTtnhR7lVwCuad8DDE+0TUjLRA==
X-Gm-Message-State: AOJu0YweMPox6R9BsZ9DoyLK3CgCE61IJv3p2Sq2+vl4reet7eJuKiB3
	54FbUQ9T6Lw/2VtZyZqa8OM4T0J0Cv4SScC2dVqqY6XNvVB0eHUA
X-Google-Smtp-Source: AGHT+IF+xzkFVC2PNDCoMZ4cYbJ7pGKdYLSKI7qsVUjLhdvt1yy/N6fY8nZTCh7IZmd2ZSmy8Va5eA==
X-Received: by 2002:a05:622a:15c4:b0:42c:774e:d63 with SMTP id d4-20020a05622a15c400b0042c774e0d63mr25905791qty.22.1708544511310;
        Wed, 21 Feb 2024 11:41:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5a88:0:b0:42e:1424:c70a with SMTP id c8-20020ac85a88000000b0042e1424c70als4870092qtc.0.-pod-prod-07-us;
 Wed, 21 Feb 2024 11:41:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW5Zpu3nWtSqV1IaTj7y6XLqMMbNvUxCH+JamujD99ZAqpG1QOGFBpsOgPikX4xP2amsPQi1OWvYi7U5+qy3aGrELvOFbCUMNxr2g==
X-Received: by 2002:ac8:5a86:0:b0:42d:c831:6a3f with SMTP id c6-20020ac85a86000000b0042dc8316a3fmr25739808qtc.26.1708544510136;
        Wed, 21 Feb 2024 11:41:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544510; cv=none;
        d=google.com; s=arc-20160816;
        b=Qfy9EV7kHfPY3IqclyRJB9rZOdj/sVefHWTsTqhk88zovQLS3HgrN6e5FATARqutRh
         9YDu1uM0cXBTSOY2vI4N2/RDZGHDtF/4f3VZMF3aCute7VnnoRgepYkVWlSbQFRZx7Wy
         PACydKDdpQ4FLTGcEDwsyV9EqLgZxPBy1lBYo7tqfbJDp3LM/bI6qk8L/RbN9WRuBisd
         WW3InWodvjk0tkZkqGzxYR56VKCfuLPxcTLcPw777krk44TiG8ityM4lxDMM8A1MMNK4
         ydxbUx9dQR6/9PcyZe9z0VJ4xrND/clvAQxsr0okF7IUsUTWyeEhjX5oWDIqRFXFYsOp
         HJ5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:dkim-signature;
        bh=X6Mc1467Tr+n3B+nCTUL6nWniTp2NFe2UCsWnkAH0JA=;
        fh=XJf/4Ge971BhgOM76PD9S/d4JS3AL96rxIyh8tj4LOM=;
        b=cNNhSYysEjVq70egSWMrDMkFP3H0Ca2GdnkQE5XErGXnpoC/QMyc4euHFytDa2TXcc
         Si9B1EKVYG+X67SgEwAD0VS4YZZgM4MBEtTM9FcZEA4Zu560Uyp915gSAOMpFv7VoC0P
         QZDZ+5BVxBAgYVg4uVLuKtkLEOQL3w9G0nh7AkKj13ZNammG2aAMtiI9toQFGILLUP73
         6AzcXsgohQtOOQ0dOIkP4e8PH4EB0yMCi+kKRE5Amm4y860t9ZAToRjg1qOQfWZUvXNO
         3Bgjdj8Qyz5jqI4rl3d73ZF6VeIt/7FPhCoqfOFJai9E4hhtp/h4BwNVH5wNMGMQI0Jx
         Fqfg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kvwVPRBy;
       spf=pass (google.com: domain of 3_vhwzqykctaegdqznsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3_VHWZQYKCTAegdQZNSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id l20-20020ac81494000000b0042c35cd8321si706319qtj.1.2024.02.21.11.41.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 3_vhwzqykctaegdqznsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-6087ffdac8cso18221577b3.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:50 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVpb6RyG2zEAGAAs7ng3ePFO/LTi4QDqsF7ngkxq5eXY0t/hMNYO9ybvH3TaflmunEOSUbN16RDkNn/C7nU7PGsjV7H5FoXGwAPVg==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a05:690c:368a:b0:608:55be:5e3d with SMTP id
 fu10-20020a05690c368a00b0060855be5e3dmr1661247ywb.0.1708544509616; Wed, 21
 Feb 2024 11:41:49 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:37 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-25-surenb@google.com>
Subject: [PATCH v4 24/36] rust: Add a rust helper for krealloc()
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
	cgroups@vger.kernel.org, Miguel Ojeda <ojeda@kernel.org>, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	"=?UTF-8?q?Bj=C3=B6rn=20Roy=20Baron?=" <bjorn3_gh@protonmail.com>, Benno Lossin <benno.lossin@proton.me>, 
	Andreas Hindborg <a.hindborg@samsung.com>, Alice Ryhl <aliceryhl@google.com>, 
	rust-for-linux@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=kvwVPRBy;       spf=pass
 (google.com: domain of 3_vhwzqykctaegdqznsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3_VHWZQYKCTAegdQZNSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--surenb.bounces.google.com;
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

Memory allocation profiling is turning krealloc() into a nontrivial
macro - so for now, we need a helper for it.

Until we have proper support on the rust side for memory allocation
profiling this does mean that all Rust allocations will be accounted to
the helper.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Miguel Ojeda <ojeda@kernel.org>
Cc: Alex Gaynor <alex.gaynor@gmail.com>
Cc: Wedson Almeida Filho <wedsonaf@gmail.com>
Cc: Boqun Feng <boqun.feng@gmail.com>
Cc: Gary Guo <gary@garyguo.net>
Cc: "Bj=C3=B6rn Roy Baron" <bjorn3_gh@protonmail.com>
Cc: Benno Lossin <benno.lossin@proton.me>
Cc: Andreas Hindborg <a.hindborg@samsung.com>
Cc: Alice Ryhl <aliceryhl@google.com>
Cc: rust-for-linux@vger.kernel.org
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 rust/helpers.c | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/rust/helpers.c b/rust/helpers.c
index 70e59efd92bc..ad62eaf604b3 100644
--- a/rust/helpers.c
+++ b/rust/helpers.c
@@ -28,6 +28,7 @@
 #include <linux/mutex.h>
 #include <linux/refcount.h>
 #include <linux/sched/signal.h>
+#include <linux/slab.h>
 #include <linux/spinlock.h>
 #include <linux/wait.h>
 #include <linux/workqueue.h>
@@ -157,6 +158,13 @@ void rust_helper_init_work_with_key(struct work_struct=
 *work, work_func_t func,
 }
 EXPORT_SYMBOL_GPL(rust_helper_init_work_with_key);
=20
+void * __must_check rust_helper_krealloc(const void *objp, size_t new_size=
,
+					 gfp_t flags) __realloc_size(2)
+{
+	return krealloc(objp, new_size, flags);
+}
+EXPORT_SYMBOL_GPL(rust_helper_krealloc);
+
 /*
  * `bindgen` binds the C `size_t` type as the Rust `usize` type, so we can
  * use it in contexts where Rust expects a `usize` like slice (array) indi=
ces.
--=20
2.44.0.rc0.258.g7320e95886-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240221194052.927623-25-surenb%40google.com.
