Return-Path: <kasan-dev+bncBC7OD3FKWUERBIXKUKXQMGQEPBZLIJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 82D35873E96
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:39 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5a05537c0b3sf7220730eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749538; cv=pass;
        d=google.com; s=arc-20160816;
        b=0FAt/BEk/5WindUQrpCtLQ0mOS5BZQQ0gDuzwvMlKcnwltlimM5cBUN55dvB8aTvsg
         8GGbFnorPGiJf7PIKq69raq8G5J9HDT8sd21J62nqJU8ssgfL+w7oUDUNb6GD9wi5Zyi
         Jd+rDHtXL3jz13vUDZTFZNcGxFvmyd5NPAErrNl2naM4RPPwwiSjBXKPfc0bAgEmP5i9
         ah8S0xqBS3RuUPFOzR/3KVUmVrfM2UEUhTpnih/dxpbNVAdhPQhK8mzTUELxhFlMieEu
         mz2EfSNt3ISQ9QKYdKEnRXHQGKrJB4Ul6IFwQn/w0jUdEzD+XCXgaMTwlHuA9C2EOmz/
         C4Ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=z08KONY0rPTiSFAoSFbHEfhgT2QE5GQwAkmhr3/j1tk=;
        fh=LvUR2C6Y5MWBJetYPASwYWUHN91ji1ri7ynhB/ngwxA=;
        b=lpm6jy/E7AJuk5c/jc49usT8lH17qSkh2qKJqJTdo2Obr6Q/TPZcBuWilFCM2CS36M
         q4U9Bm8AZWMnDEQoaqH10tPxY/XTDgmFQ2k9kRK7CRIH2qXxjd/01xQknwg3dfcofrFQ
         OaFYzQdtAmwMcAJvXM0lOncRnwW2sAeJWbnGZlnCOUIPM2ca2AgfvamQu8FX2I4ftMtM
         28oya5Ueg2bNo287u4CINAWx3EyoigpQIoTdoLTsvLHMJ/UXOboKpwojqXNwM9lfhi4N
         wN+OCn/5L+D2AGwpqJReMvgLU03qFmff9BEOtgYm8bfFhqilQDM5In3vxPvwm5s7yAD4
         Nyng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2k90qMAK;
       spf=pass (google.com: domain of 3ilxozqykcwmtvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3ILXoZQYKCWMTVSFOCHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749538; x=1710354338; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=z08KONY0rPTiSFAoSFbHEfhgT2QE5GQwAkmhr3/j1tk=;
        b=L744lfaDhm8PmTlrHj/cMaMq72zKds0WMjpn3PVR1bdpxTBB0n75lCQD8FlMRCLwCF
         oKoWluf0BVQM+QvtMp8N+t5HiarIJgUibJBvEKaav0xcgJAXUxLVWpUeA7obz2aPp+Yd
         0z2tZPW6abKXTu+hDrR1osq5YzKdKoGppe0v6U7nUAS8XyzlpKvyDVT6TCAGFsx1oHuE
         2cviHqncEyEdV9jvA8LVGGsHeOQPuKxgu4AnVY/nYlTYIK+fGnaq4snDEonYTTeVINH6
         4KFK5T9g9kXXF5i5tl5JAvK6w6IFFIC83BYVC/4NlcLB6nXAGk+qWqb+sDb9vF6pdpkE
         0eTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749538; x=1710354338;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=z08KONY0rPTiSFAoSFbHEfhgT2QE5GQwAkmhr3/j1tk=;
        b=qsrLICCbdUnDRN9TrgHpnZqCLt+1jW74Hxis+lKFm7ACOdO0O8Szk3WGaRLQYCSnsk
         gD7d7LhxorGpc91p99AlUaghzaqm3yGjtao8ysYnYZ0e3CnXA49RN6PAdhxBFUhaXQuw
         5PHyyCsza0II/0Xpra0oVMFOkWMFcy0bQr7YJ+1aacDWSz45ofpO4iijpre8uY6BtgOj
         n9exE06zzf2v3w8F47odXW+nOp0xrHZluGP/uGFG4Yeyc6sQc0vr2qEEZNnizUvv0mR4
         HgKtEMUkeizh1XPa5pgDCiG1mgWdqUvF80UVjewOc9cUJkhL4o3NVEQZF9xy3oVkW8N3
         WZhQ==
X-Forwarded-Encrypted: i=2; AJvYcCV9e1jSXFOBUJHygzPhPF4dUtge8T90VWdB3TEeuGeQk9myoUw8kwYWzLohKqYkm48yH+iv2WAGHK5kGbpSJXXwInbJ5BF5RQ==
X-Gm-Message-State: AOJu0YxDeuCr7uVBvLCwg6U0jPU5uladkguVOlN3xLMnPb3d7oMo4zz6
	h4hZKHsuWk8EeIn+qtbIz0Fvl5+bLsEL6dpGqQ0FueNs146yzv9/
X-Google-Smtp-Source: AGHT+IFmXlDtAZScnVwPGHeSpkJLpp6ijnvjUpOQ50ZuNeWpeX7Sl2+cwRe/vXdg94LuYWejBkLWTA==
X-Received: by 2002:a4a:3856:0:b0:5a1:a595:cb08 with SMTP id o22-20020a4a3856000000b005a1a595cb08mr927284oof.9.1709749538203;
        Wed, 06 Mar 2024 10:25:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:7647:0:b0:5a0:3387:2adb with SMTP id w7-20020a4a7647000000b005a033872adbls83231ooe.2.-pod-prod-05-us;
 Wed, 06 Mar 2024 10:25:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXAXfrGuuAfptOvpjjdNK+YYzS//kEvj+8qokxDdM8vl2Aao1wRMarOM8s0aZIMX+KHp9n1JaItwwuTfbLhafzIdq63MlLNLOSxWA==
X-Received: by 2002:a4a:3856:0:b0:5a1:a595:cb08 with SMTP id o22-20020a4a3856000000b005a1a595cb08mr927220oof.9.1709749537167;
        Wed, 06 Mar 2024 10:25:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749537; cv=none;
        d=google.com; s=arc-20160816;
        b=ZFSCzW+LO6VwNX3dNWlb01gmlN4arLHD5mxCWQKnYAZIyKKN1ZxQ6UldXH4aQeUMZ2
         /sRytXzTJO5p9+RENTjLmYekDsLU7jxYZ8eRkYGduIUS0MFDEwKmQa7bfgO0nu7p/XPZ
         vI596KsNyHUrsVf2T8WgqfGgvvHNRZykTWOcz/+I75EHZ//5/R5bF9G9oAiwlAvBjYd3
         FAu83GCzqJTRmbO7YGCZ3PUOc7Fe79tUO0CA3rSh34sk1+t3Rfrx1qVkJ8T+rfI64BLJ
         OM+//xpfOtsoaeT1lDPsGrVlRmWKYLQBGsncyQWpzGcPpNC+X7EAL/vz2HgPywGMLMTo
         /ZEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:dkim-signature;
        bh=K6AcyGgSKYmz5a5MAIaPTUUBsabHZwFmfRjLl2PG8hA=;
        fh=8fL6wAhceM4DggJw22wXqinUV4Z/+UyP+DAtYDADJPM=;
        b=0fsaJ2YVd7nYyu6WrB7AWctFDxODeyDF1UAI2VxAM8fhEGVym43BzQhG9HxwGrVzn6
         hws2lWR2GV3KVcITtPp9cmEOWmbwNXFH9eyS6T4LsP1FLjBzb8gRfz5zMopXsaqxDGBD
         3v1pwMfWcLwbpjURDgLD5painlUJ8Ll75zeYedGgfI7dDsl+SUAnsBX80TMTgNWQFKSe
         BNRsirG7Zp//e0KfH9YqkWSLTmjC+xMljLn/uc5p2CNlZ+nrZ8hcE8ZPgnd2g2M0UfjP
         6iGZ4WV6391H43MWhfC6GMXV9S1iPmkCC+7YaVlqWKsUgyu6k73N0h6Vjv03Pj/Guq3K
         aLZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2k90qMAK;
       spf=pass (google.com: domain of 3ilxozqykcwmtvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3ILXoZQYKCWMTVSFOCHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id z16-20020a0568301db000b006e4b3e2c386si841368oti.2.2024.03.06.10.25.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ilxozqykcwmtvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-607e8e8c2f1so115467b3.3
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX5M12q0B733sCnxYdk2834uISWVQclBMPrJ3x+LFEFneajBt50FB1z538t0UKZGACxDlO+JaEAnVKVYV4z4TqvVmvSrkZQny2TrA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:6902:18d3:b0:dc7:865b:22c6 with SMTP id
 ck19-20020a05690218d300b00dc7865b22c6mr633022ybb.8.1709749536658; Wed, 06 Mar
 2024 10:25:36 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:22 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-25-surenb@google.com>
Subject: [PATCH v5 24/37] rust: Add a rust helper for krealloc()
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
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, Miguel Ojeda <ojeda@kernel.org>, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	"=?UTF-8?q?Bj=C3=B6rn=20Roy=20Baron?=" <bjorn3_gh@protonmail.com>, Benno Lossin <benno.lossin@proton.me>, 
	Andreas Hindborg <a.hindborg@samsung.com>, rust-for-linux@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=2k90qMAK;       spf=pass
 (google.com: domain of 3ilxozqykcwmtvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3ILXoZQYKCWMTVSFOCHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--surenb.bounces.google.com;
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
Reviewed-by: Alice Ryhl <aliceryhl@google.com>
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
2.44.0.278.ge034bb2e1d-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240306182440.2003814-25-surenb%40google.com.
