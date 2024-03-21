Return-Path: <kasan-dev+bncBC7OD3FKWUERB26E6GXQMGQEHWYMGIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id B4D4A885DC1
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:38:04 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-7cc764c885bsf125304039f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:38:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039083; cv=pass;
        d=google.com; s=arc-20160816;
        b=iHD0jd+O+AxJM9vj875x8VhJ91qmOOht4Spku3Po6ttcsRo6vXvGsh+IZaruGZfR1W
         /v+rbzxbQ+e4ssCM/c5gnHSminagE0q0ygBp22rDZFzJE8wLpR1Uu4paxIL+Pc8fOlM7
         8BQjk7/CGotyVII9rgIeBNsb4HzGKp1bQO47nS2g7MhMS8kcmKdk/Ugd/+dhPDXAL+9a
         1EUYnqITTIlcQQ7dmzAW/eY0JXN1/t1wDfugnGVk4WcleEE0rUBYyiKTySIMTfPW4Dti
         mim4w6Yiw/ZMiwG3PSpIDrhBb7PT+UM5CmxAdvs+c4koMr+yWuQFvy/SFYEsdPYmVenG
         r80w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=eYOGakAZI7KyrgYDW8STP4da41cddHUASQXZJodbV8g=;
        fh=iVdbXJgCtMdMQhQef+xRFRb9FIie2PrTJBMNm4ND1qM=;
        b=IogcWreaJCbgPPYGy3eDDv/nNSW6vF1+CmEvYNseAo0kQtqzyjJ3cfJddW1V6Pfx+r
         1F9ZAa8bR6V1/MC8HhDVaDdjlHBegSq98CnCGuy/kXl4AP8wE1NLTbMiMC2bP3rOFv1E
         oVDdQ+vTfK0VS1GrjfxrgRxq/SXtRV8Ew6HdzYLqGbOdD8QYL0w3jC8xYY74rCW+0Y9S
         x1i0gHrQceZGKQdyANOk9yAdkLicTG7AZ3RgZfQlFcEsNb6jx9eu1EMuqLK5hdWicXxE
         91BvagjY3UQBB5Ki2RNn5hV1OkLGWFZ2Pc6k4/knfkmys3+r6rbDkTR5z04ToAYf/AZ3
         sVTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TvqWFlux;
       spf=pass (google.com: domain of 3awl8zqykcvygif2bz4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3aWL8ZQYKCVYGIF2Bz4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039083; x=1711643883; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eYOGakAZI7KyrgYDW8STP4da41cddHUASQXZJodbV8g=;
        b=g5XMrjxwf4r8yRkf5wgrcuXcG9ElCsEIgABv9w0LTbgVQiawELjngSi4+iS6HMh7oz
         gcuAd1kjMo5ZpFUfiVgBNDmmJdlxvmiUma+oPTJH9ZaA7JoQBwKBqULKW3ZM5RLQeZPz
         HcW9lh4l3cBqxnlO6e9YIFUSET5cBcmnzQiOATyUewmFJ3bDLxvO5vup+vMOkBYMYFyW
         95Guyzr2Lb1s3CqXL4+H53CrsCByIP6TJt7jqYFYjBm5jnoRDK3oHJ73PCvVDP8cygTI
         CwXAflk1Wvy4KiJn1EICpM+yUHENQCi1I3DDs4klDfoHnfrEB62iMQ5gW4TmRiCh1juo
         YUmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039083; x=1711643883;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=eYOGakAZI7KyrgYDW8STP4da41cddHUASQXZJodbV8g=;
        b=LNJXQfd4XGudJerF1W4YSqd8AVrqeOmwcSI1NZ3CQSzwhA5oBMd4ZwBMKUAo2RU/K5
         MNOHf8Ajvq8TlsPLZmxbC8ZzZ90hg8LCO+1wGGPvDvpgvwoMkAeCbm1MHQ4/KmU5Mwxc
         2wjdTLNX88D4SiYBEyW1ga7PhI19GcVbaQAJVLduJnXB6kF9Qe09Wt0qsWm5ZZtGTqcL
         QuSpjYBmS6Sv9DBqT7NRjut2e/eR2OZkPcJUiT3ryj4aAY3ew0utKVwR3n0b1PAUifN2
         gz/kwOHaM7Rz4+XlLsrVpbk5iQAsctBEe4SbO7LVcpr9xbGeC7treBOAaGM3R0ocXMA5
         kOXA==
X-Forwarded-Encrypted: i=2; AJvYcCXxYtMnqOkiAqK9qNhk4CRv26Akt9y6kPkUDh+Z9NFH7Vz8IXoZaSeb0eoTC/D4l9Q9UmghLImcXjlb805teJbOYClHfnO4OQ==
X-Gm-Message-State: AOJu0Yxc/caRS9r27duOXO4aBJBfkW1TMElHWwn9q4WGP7oj8swCuQfa
	6s9zJ79YwrJre/wWniyi+A5jyHY36jwgwQK7iDUDU10tWi1rkyB1
X-Google-Smtp-Source: AGHT+IH3V65si3gqyW72T1tdMy40g2XkJzqs90erv1PYs4O0azeTsY85NeN6JmvEtgq2D5tgfN35Bw==
X-Received: by 2002:a05:6e02:1a8a:b0:366:9511:dece with SMTP id k10-20020a056e021a8a00b003669511decemr51226ilv.17.1711039083382;
        Thu, 21 Mar 2024 09:38:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a87:b0:366:af4e:9df4 with SMTP id
 k7-20020a056e021a8700b00366af4e9df4ls823345ilv.0.-pod-prod-03-us; Thu, 21 Mar
 2024 09:38:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWlmWA5wHSsAfcMad/GPd07B6o+R4G08243RsGINdnSY5HeG/9Rwk0J5MZ+erdRRMYyGtUDcoFVRMchy7l33yUvbIDpkGFtRGJz1Q==
X-Received: by 2002:a05:6e02:1148:b0:368:4a19:a840 with SMTP id o8-20020a056e02114800b003684a19a840mr24229ill.22.1711039082413;
        Thu, 21 Mar 2024 09:38:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039082; cv=none;
        d=google.com; s=arc-20160816;
        b=I+xAMHORVWw7SyROjSEui5cPcEcqclLd1UwtWIn76v2Rn1xx2xiy/BiD78UlUeeUhK
         Zt1L3AKrnj3spfU3/54DqGQz9EDMlnQfbut251OaJL0xlUDa+icKBtoLEPVdnqCqzpBx
         uEnjzfbBH9JLtDGx3KvwUipYEtzuW7G7zIBPVXq6P/wfkjImv6xV2O1SidzFlNz6vdvA
         STb83So8xxhyFms5msRcfhIQIBv2gtVDvLnkPvYolHfYbgDrIBFQDc9gQRgPajzwsYWg
         lPPWKM5AbZSepy5MBb51qxrxyZbszokwlIHFjuxd005U6NXcO3iOxkhtM9ZBrB4kID1J
         Z1Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:dkim-signature;
        bh=s40WFNE8AOKkW3fMlFNAMtyrdkqCS9mljSRdY//hl9w=;
        fh=MZswi4SFGHO7cmcLy4eLyIK38z9HylJzoLgudsp7Bic=;
        b=ApLrhX4fGLNQ79uNCVU/f3vVmRCmU9/G8plYoGdN4CphLefNH70W0FhLMljPonY9JK
         fJ7QnjoFF7YWsle2r/rIbS05MQkccZK842HL7K/Q8UqHXJA0OTlXH8v90i8LrQbhkody
         XM4fEo+MUaba83xhiP+IkMJu4GycGrq9dS42dFuvmiTG2vLVGujQANMKExPakI/Qjs69
         kSWbYtE9XcZH2WoNhJqhjmxp1pmoeRaliQry5lFkuZK88EifCpdtvdyddTKQwGb0R0ma
         3u06+SUUWENJXpkK0ueD019ho92gwVEtVonMH8P/B/FI8rXLjbqf/6cglNBV93sEcUoL
         Ty6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TvqWFlux;
       spf=pass (google.com: domain of 3awl8zqykcvygif2bz4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3aWL8ZQYKCVYGIF2Bz4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id g6-20020a92c7c6000000b0036503a50b98si6764ilk.4.2024.03.21.09.38.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:38:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3awl8zqykcvygif2bz4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-60cd073522cso21754347b3.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:38:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU52SByxggL2Ng9Q+ggqJDjmJs7PANfYS/oMXKbxo3Kbv1wYPPT7up1QhbWqX/oz6i0NDbwlk8mUcNFlKvlCuZwvv5BsrmZGKZ50w==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a0d:ca91:0:b0:610:fc58:5b83 with SMTP id
 m139-20020a0dca91000000b00610fc585b83mr1061193ywd.8.1711039081806; Thu, 21
 Mar 2024 09:38:01 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:46 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-25-surenb@google.com>
Subject: [PATCH v6 24/37] rust: Add a rust helper for krealloc()
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
	cgroups@vger.kernel.org, Miguel Ojeda <ojeda@kernel.org>, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	"=?UTF-8?q?Bj=C3=B6rn=20Roy=20Baron?=" <bjorn3_gh@protonmail.com>, Benno Lossin <benno.lossin@proton.me>, 
	Andreas Hindborg <a.hindborg@samsung.com>, rust-for-linux@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=TvqWFlux;       spf=pass
 (google.com: domain of 3awl8zqykcvygif2bz4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3aWL8ZQYKCVYGIF2Bz4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--surenb.bounces.google.com;
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
Acked-by: Miguel Ojeda <ojeda@kernel.org>
---
 rust/helpers.c | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/rust/helpers.c b/rust/helpers.c
index 70e59efd92bc..858d802abd11 100644
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
+void * __must_check __realloc_size(2)
+rust_helper_krealloc(const void *objp, size_t new_size, gfp_t flags)
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
2.44.0.291.gc1ea87d7ee-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240321163705.3067592-25-surenb%40google.com.
