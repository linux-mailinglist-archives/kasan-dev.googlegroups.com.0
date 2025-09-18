Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVVDWDDAMGQE3MDQ4QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 82B86B84FBA
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:06:15 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-333f8db9035sf4808861fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:06:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204375; cv=pass;
        d=google.com; s=arc-20240605;
        b=XvbjLtTocBeFgxlHxzCNTKTqgmndVOK7CsYCxazKHcg37hAej3qNu6+v0D8vf8aZSr
         J5qZb06MDiBnNRo6zYXeIxq+8V87EwUoY+KXOn+zlhcNBs+dhZYAGtJgBY3OnxlOTez5
         8qdPd7VDwZsyIUgO8BzMm0fsXw6dzKGow2VwlCS/HElC77Co3USFYCOM9D0kSVKBQrnA
         aHOFkXWianhRCQRmVrI0h7KshLtDTrQSLb+pdh3KqlDRAXIxCwjkPdz6Fj/QkFGGD6vs
         jzsDYRBmCCHOOVTH7L/M3tyV/IaH58U5lb7fmAg9hqWxjzHGE8JCOmre1Yne70FrOcs5
         fPWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=5vkcSvqm4jLAmqbHmg6XUXFeeM5QGpG8nNAczXQylg0=;
        fh=8+yd0aQlgXuBQ/7282T+MROuI3tB25qS68Kt4IAzE1Y=;
        b=lBE5l61t5aHW0Eo1KEtpXZbzGxQbf9ghY+rYGqRskwsQtaWMsDrOaYtwx6YGBwaY5b
         P83x/ZmD2Zq145AUQL2QnjqYOfWxcas7xAg93IZdrDE0GaQ00mQIDEo0cUBbgFwiF+Gt
         gflcRjN8XaGVYmIWPlXwZarWrEbXAYPjWHrrfhgYtcQ258lBC4k21BEm6AKJ8VXOqGNP
         IwB8uxUpnDhCQehEPrBQONlGItYt6dUL0yZeHJDf64bDI/I06vOEX8I8zG1oOFz+Cukt
         hyN7Iyrj8+wdSyfbCtkJn5VkK910Y3U2kMRqFLVGvEfjY7i+lGUBIQyg6mpa+ZN7BNEQ
         WSAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oA8eTBHY;
       spf=pass (google.com: domain of 30hhmaaukcxmvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=30hHMaAUKCXMVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204375; x=1758809175; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=5vkcSvqm4jLAmqbHmg6XUXFeeM5QGpG8nNAczXQylg0=;
        b=l2+bnNEKjUar32hdu1kVYfwPTfXu1Rbd7vYUXqQD/5n8KJh016VUjG89luAod2HiOl
         sRr6qGIBFrESMf8zKVe/nfpm3ZBsCgW91eKsOHvmv7JtTJEh1KZ2VKoy7d9TR+hrC5/S
         069QxZ8f/MSjD4Waf2nqkNKQ8N9QcrwRqy/WTyNJYj62VjeBpYv4M+LGa2JSfk9HGrXv
         nEbZHrTNnZXkZdsTV8vSJG+rBzqQyXxl/9ySrplCRSbHqGfmiY+exEj26Jbh8C6f5Uld
         oi2o3eNUVGe6yUBs79AGZJCw0ocsvWpLLfh+GCAjJ3Vz2sv5VQ4xg7+zqn6xqDm5SI77
         RxMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204375; x=1758809175;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5vkcSvqm4jLAmqbHmg6XUXFeeM5QGpG8nNAczXQylg0=;
        b=Xc27zisQI9lok4/DiEZQnJu8I36m8tOBnJ7yyhAafcMRJ7J/5fuMQE+ALaCW/ugNih
         uzUVBSrNYZYZOvp6G8L8AxgixDWAtnOid9w1P73ePk7BsqLlzhfcdCOq7o8Z2+swX2Cs
         WyqV1/P3ECUO6eABkCaOwVYSHWmfZ8+8hIdazoHltAkpCGQ5AOTQRAHXdlcUSM1tvpDf
         RGboPdejccu+e9y6AoirL4AprV6SBx7GZwdQE6UGNODTn0z+O+Z16H6m6DyenvVME8Fq
         o4OJFVDDq52sN7Z//OBANw0bHOEZ2jtlMQelZ2zi4FLRPJdS4vVi0RdxEQqDy5I3LUhz
         5+Cg==
X-Forwarded-Encrypted: i=2; AJvYcCX7ISN4SLDQW0Cm1KoevAKH4U0tnj0hltbRRMAjaSTiJVjKkYUxphLIqfLVjVW7rWgZJnlOjA==@lfdr.de
X-Gm-Message-State: AOJu0YyEDWpB2pc763yY2BS6JKUEU6IY/sUelEioFQXJKkBXbiBGN7Rv
	cVH7mWNK03p4ypyD6D5DcoTEL5Ps7X8s3kM653AoSzvuTpLIJHcURyox
X-Google-Smtp-Source: AGHT+IFC1GDqp6iwbtTysQjVIU+faClnENh08nYiZcnFmWQKaUrtDMPgLNuv4CM7DGYClZfrNtQYjA==
X-Received: by 2002:a2e:a9ab:0:b0:333:bb82:f8af with SMTP id 38308e7fff4ca-35f650e8452mr18282631fa.22.1758204374607;
        Thu, 18 Sep 2025 07:06:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7SUdU5SlgilV9lPDQBP8ZfEg7FkTjuT7twLoeMm0FXvw==
Received: by 2002:a2e:a37b:0:b0:335:7e09:e3da with SMTP id 38308e7fff4ca-361ca3d87bfls2228641fa.2.-pod-prod-04-eu;
 Thu, 18 Sep 2025 07:06:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWhk6o3Orv8LAq0FOUcswIZFRU0f6BOACk7lyAPYZEn0pN4NTmFFT2FstL0o938LMsTwQ2UcTHvhmM=@googlegroups.com
X-Received: by 2002:a05:651c:501:b0:353:6628:54b with SMTP id 38308e7fff4ca-35f61e8bc07mr22498001fa.11.1758204371523;
        Thu, 18 Sep 2025 07:06:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204371; cv=none;
        d=google.com; s=arc-20240605;
        b=jyoS5InJcxQlHQ42PLaL4wpRMERyGurKQTct2hIo/wdEO5sOMSahx+CizKWzFaSZSR
         S/N+ECpEr/fq8XmxIxkD9ydHOOQKtuFbAOHFUSB7tVRbIVaX1lrnJawY4MJb9lty/IPJ
         0lbNzYFv27KUX/5N7ZWD5+IRFfaejIwI0RBdHBwDCA0ier5aoucuTTIMnD24YSK9idO5
         xuhKG9/mFjaDzhPqvL2RQt9wp+R6Nx8wqKIK3sWqZjeZXMCxJTOktfwDJbZg/z5gqIeW
         vQfL8Ur+EF8Ank2mat+rIvlLlSIo8wODMP6uJM9bIhHSZ2l+Ri8yvm38NWrLzpcYvjTz
         CiUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=nMl1c+2bip1CSgLpfgWYnQ0cyIrLa9qex036CuBQq14=;
        fh=C+lLkZX/aMq28edKUdwgHqpvOtN/l1v6uhdhU9MsBAE=;
        b=GvnsCrii3UG2yIlgDQsCJo/JDoMbd25FkgCh2Odax/xC7F8w9Mic9n+uJ5XiMURnQk
         AZ88Qaf+umIdWSyX1G0BPIQihchiICEyFRvDtmk9VafXPzp9agXoKz1PzQdTUqdIWv9t
         ItMNbKj1smnaqoniR9WJhfoQEI82g1zczsZxe0k8y1e501OH1p1Ryy8aJY9NvaLiWwn4
         9mojso1lcRVBwIL54fh/UiNxK3MdSqSXNDiem61vWnDR60BDocDa7CqfNaZuswPLzzGV
         oWPk3lp2+aL2hCxb9uoZuoob1eVgt2xMbQhrtQgBxl38NQOUNrjLBnso7WOhJ2vfi5TK
         lysw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oA8eTBHY;
       spf=pass (google.com: domain of 30hhmaaukcxmvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=30hHMaAUKCXMVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-361a2c9b569si578701fa.2.2025.09.18.07.06.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30hhmaaukcxmvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-45df9e11fc6so7235995e9.3
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX/xe2z607oyecVK0UO3fnzFziUo2QYUMmeUSt/w651CY2qNmMy+j9famD6O3fyICv6iEdz8BG0ynE=@googlegroups.com
X-Received: from wmbay25.prod.google.com ([2002:a05:600c:1e19:b0:464:f7d9:6b0])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a5d:64c5:0:b0:3ec:dd12:54d3
 with SMTP id ffacd0b85a97d-3ecdfa1eb5amr4911144f8f.35.1758204370434; Thu, 18
 Sep 2025 07:06:10 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:27 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-17-elver@google.com>
Subject: [PATCH v3 16/35] kref: Add capability-analysis annotations
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=oA8eTBHY;       spf=pass
 (google.com: domain of 30hhmaaukcxmvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=30hHMaAUKCXMVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Mark functions that conditionally acquire the passed lock.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/kref.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/include/linux/kref.h b/include/linux/kref.h
index 88e82ab1367c..9bc6abe57572 100644
--- a/include/linux/kref.h
+++ b/include/linux/kref.h
@@ -81,6 +81,7 @@ static inline int kref_put(struct kref *kref, void (*release)(struct kref *kref)
 static inline int kref_put_mutex(struct kref *kref,
 				 void (*release)(struct kref *kref),
 				 struct mutex *mutex)
+	__cond_acquires(true, mutex)
 {
 	if (refcount_dec_and_mutex_lock(&kref->refcount, mutex)) {
 		release(kref);
@@ -102,6 +103,7 @@ static inline int kref_put_mutex(struct kref *kref,
 static inline int kref_put_lock(struct kref *kref,
 				void (*release)(struct kref *kref),
 				spinlock_t *lock)
+	__cond_acquires(true, lock)
 {
 	if (refcount_dec_and_lock(&kref->refcount, lock)) {
 		release(kref);
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-17-elver%40google.com.
