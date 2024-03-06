Return-Path: <kasan-dev+bncBC7OD3FKWUERBEHKUKXQMGQEJ2N7MRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D5CD873E86
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:22 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-1dca68a8b96sf51205ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749520; cv=pass;
        d=google.com; s=arc-20160816;
        b=aCEo+MeLlcKk+1BkK7bnCVUZOYNo3DxtsODgKxtnlcGxrB9JAfhlyZLCzHGS0WNlMV
         SCFFO7d99zBXy5Tfi6ZDRAwzTgKf85RWUA8VBkdZnEp+AeJPBNaXioMYY7DYuWWqVevN
         CqDNxUD5HOcV3j9Vz3qiBnWmkaPoHupYeH6v7pNIQGOBD2KSZUluxXgx08BlGE6L6fXJ
         /Q/KNvGJgLp4fovjNLKF91lng2XeRiFfGLx39N7/YZTjEpd5pnBBq7WK3+NvS0RZkXVZ
         7FyIJcccI4EqRp/hQ6UXnkaqpZf/dYErAeL5Rf6UKDh2E4WhZBkudURWfYsYyEGOTVQT
         L68A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=am/6OSmy5XAKbTp4LLgKFovNKTFqkA43db1ERcwdkK0=;
        fh=D5c7axtx2ZTY0SK1/r501FpSaT4G0kJnezgs+ykCg2U=;
        b=mENfo4fBwEJyvEB4QxzzoBdUdLQziHWHkIz8PNSohey9PmHwavpNZDO03/U4peY9ni
         Ra5/DbcXlugUwcIR6dDmRahxS1cnzUVZY5KdCiHP3jd7b/5uunFwAAYouNYsrSNusO/K
         6xvrOQMorhsqQ0mXZcLT3m/wE6WZzwq8pFacf9MtSqQQxLYNvos+5FszHDZY0uwvAzbF
         owb+iug/u1bTsWfoLq5uKiCW1f4VL5hZ19uTOsbfujfPjB3aY3SJASHLJTy3vRpZIKXC
         yVk7sU70JAT0O4bCqW5Th0THUKGvr8uEnh5duokHtaWvSFcA3Z3i4bi1RURwkTHiZ6Jz
         JUAw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3u3gPdxD;
       spf=pass (google.com: domain of 3d7xozqykcviceby7v08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3D7XoZQYKCVICEBy7v08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749520; x=1710354320; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=am/6OSmy5XAKbTp4LLgKFovNKTFqkA43db1ERcwdkK0=;
        b=brMkdei7xBnlFE7Euk9rpPYMAvEBUnZOYVsyAd5styCWUARTJkZm1bgyf81trxb/vz
         xy7AhDSqaxYrlStPZf6wJYAw06tKmRgMfVMGtiUaFQGO7dw+yHKIzGboQCFLwyrRqU7y
         4Brq7VEJxJDJwHDzfIgKcEJA4k8Ppt4O9KRA91/G5ERcgobghsnoWHDVwXso3y0W//gT
         77V7PspyzRKMZFoeJ/PEw0yGm/x5VnGIRcn2Ne2O17lAejPtlAC5DFrsMdGPEWAKb4j7
         Ovp9oL4AFcCSz6+kofwoexVnpx2d4B1ySIsImy9UiCZMeMBGOHwwzUTn0ot0g27DO9gT
         AYPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749520; x=1710354320;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=am/6OSmy5XAKbTp4LLgKFovNKTFqkA43db1ERcwdkK0=;
        b=cOmEu125v23dRq4YycIug2sHJRw6ep7zfSniNvk5fW7vda6glxaGbpML3SnEUjyQlG
         cusBTnnkqcIuWM2swJPo0C+6Zus0f1lows0l8L0EEl2Mh/95+iHz1ZCbmPy4f8Zh83nS
         iQBmxAbyMW0vlYsWVw/XEdyNYyF9yi83AzSHoP99jYiUnj/kXEhIC8HGPKTjWKQE3Pdx
         +pme4xVychNlsTE6XyFtKLm2iSIzf5qJ4hiInsrlQR/JOKHT/lfo08udpSJDUgkDwqSh
         udcAuUIcs3c6STFLHqXhRMXmcYjwQuN2pfI86MGEHl5v/9ynIXVJpwJrw/HkCUUMKsQ3
         DmaA==
X-Forwarded-Encrypted: i=2; AJvYcCWlAFrV4fcWGR3aNB2+WiVf5FdipE8JfyOkTyPdIK+ylNn68NECdmd+nL3K5OnBLwyTI44lxYQW9PX8c95NE+MCHSoe90in9w==
X-Gm-Message-State: AOJu0Yz0ClPWih99T5fVbytKrTH0AiGC3/tmi//RUlq2uP6uFNpl5pOs
	mIEgx3Plqf8WG5dQ4cVgC9ma5u82DHt5mJq0umR16FicJK+bdl9k
X-Google-Smtp-Source: AGHT+IGdX1NVjOL81asnNdSK9PGwvOBy/t7V+5PFamah1zRgMAFKlWiaRkd23BeRtd9h4GDcpg2zGA==
X-Received: by 2002:a17:902:8485:b0:1db:a6be:ddc6 with SMTP id c5-20020a170902848500b001dba6beddc6mr40553plo.27.1709749520665;
        Wed, 06 Mar 2024 10:25:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:55d2:0:b0:5a0:2a71:8d8d with SMTP id e201-20020a4a55d2000000b005a02a718d8dls114952oob.1.-pod-prod-02-us;
 Wed, 06 Mar 2024 10:25:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVgSQFMY0eZnzslchRURPaOrkNd/YEllgSOQkVYeoroKkmTG0xv9O2h27TDoG31QGnnig7JWUXqfb8X+kucbykUH+TAYANr44jC+Q==
X-Received: by 2002:a05:6830:114f:b0:6e4:dc5c:f627 with SMTP id x15-20020a056830114f00b006e4dc5cf627mr6128625otq.13.1709749519666;
        Wed, 06 Mar 2024 10:25:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749519; cv=none;
        d=google.com; s=arc-20160816;
        b=LebfHp4O9QOIV6+yyq/4WjatkDSK9Mb1cVYC6B1zaisPAd3NM+3TxRgQ4uxS6j8kxY
         VWejIrMfqCoqlbX6jqr9q+ut9VGfBOx6Ix25yOmc0Sjci7ZCJGfBEnbbySXVq3W7c3pd
         nQVGZDtm/4Ch1D6kjODgfZEYdsxM28xviWS7L5jpwXMLGK4XM6G10iiUA2DBiqC4LwpE
         PFdix8Iw6xNccuTgEJ8IpMp5zSXd9sPkYtm8mWYro1XF9p2L1ku4bneTFp0V7LHRA2RO
         TZ9tGWwi+MVoGtdBrthleCKxanl86vLuL2PSDz7DEFkb9jXz59S7puakgc8IyYbhNeyb
         o/EQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=OEAYBW3Z4VXc6aDoxC6XGC2RO1GGkHEsC5P6UG5rRTs=;
        fh=YnUf/f6Q7zBFzUdJqur+bCn4uW3RDbGJL0QhHVBNQYE=;
        b=AZ8b5//WCBPMlN1oxgUrC/NfDFYWIwcLLssQuw2Vq/sxKriK2jGgtdgnmoX72T5FgY
         L3ZK6g0/thq0sbzv3hZBNa0it0La/4Owr4VCRHuLDT3BWWHbH31Y2OrnPqFErTxbRB2F
         Xbe3Gx25NRJx7l8yB9CSw2bCdTue7iFRgnMpFsc8RvaArdfQf8UWl+QWlsCyTbRfGFGJ
         IUpYOwcWlB5HH4nVedNMPhYYklA16wAenO5BHFRnqaf1sHoyhJMb8fvdnr99ljitzaEA
         d3lL8KSdlLc//XMh9QhdsfCWn6ovEFzVW4B+eUYY1St1fGIEDywc8KCiesuJ3uk1wsgj
         q94A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3u3gPdxD;
       spf=pass (google.com: domain of 3d7xozqykcviceby7v08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3D7XoZQYKCVICEBy7v08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id z16-20020a0568301db000b006e4b3e2c386si841368oti.2.2024.03.06.10.25.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:19 -0800 (PST)
Received-SPF: pass (google.com: domain of 3d7xozqykcviceby7v08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-607e8e8c2f1so109187b3.3
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:19 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWWy2l1LAi2nzw0qHMyOiWS/SzsHnBINWOk+2+FKW4Y77gFu24yq827vmzF/HyKG5jQxwptXba5flevDwB8dFaaAgSNn9x2neCIVA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a81:9950:0:b0:609:4d6f:7c0b with SMTP id
 q77-20020a819950000000b006094d6f7c0bmr3566046ywg.4.1709749519078; Wed, 06 Mar
 2024 10:25:19 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:14 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-17-surenb@google.com>
Subject: [PATCH v5 16/37] mm: percpu: increase PERCPU_MODULE_RESERVE to
 accommodate allocation tags
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
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=3u3gPdxD;       spf=pass
 (google.com: domain of 3d7xozqykcviceby7v08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3D7XoZQYKCVICEBy7v08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--surenb.bounces.google.com;
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

As each allocation tag generates a per-cpu variable, more space is required
to store them. Increase PERCPU_MODULE_RESERVE to provide enough area. A
better long-term solution would be to allocate this memory dynamically.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Tejun Heo <tj@kernel.org>
---
 include/linux/percpu.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/percpu.h b/include/linux/percpu.h
index 8c677f185901..62b5eb45bd89 100644
--- a/include/linux/percpu.h
+++ b/include/linux/percpu.h
@@ -14,7 +14,11 @@
 
 /* enough to cover all DEFINE_PER_CPUs in modules */
 #ifdef CONFIG_MODULES
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+#define PERCPU_MODULE_RESERVE		(8 << 12)
+#else
 #define PERCPU_MODULE_RESERVE		(8 << 10)
+#endif
 #else
 #define PERCPU_MODULE_RESERVE		0
 #endif
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-17-surenb%40google.com.
