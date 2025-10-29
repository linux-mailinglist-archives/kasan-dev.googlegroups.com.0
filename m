Return-Path: <kasan-dev+bncBAABBVOLRHEAMGQENWNAN3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id C1FAFC1CE69
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 20:07:03 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-290e4fade70sf1294695ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 12:07:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761764822; cv=pass;
        d=google.com; s=arc-20240605;
        b=DnFC3iPBjy/OVRf9jEkfXApwPg5tC/gYMZrFJRe1cuBYPAVk1tFPhFXaPitFmAXZh7
         Ukb99kEEcHoxqDFqLpNh7DpmTnPP9YJlU/T+pPqOqdVhBRQ2s9ONChhKJI9Is//pgs6k
         aj2Mlxgcs5JIbc9fQyTObLME29QzY6miPMq9nRJapzI5My5QhnttITEZvb2j/sC5Rn/A
         aKZLxlVZpeysyFDCTq03rsdG3bM5hbYHlDfEDI8YW25kZcVJNPmgiTDF2V4DaF9fHUBh
         NjFn4KfHrOuVxoFvbRsb2SB3dK7LdzmKlzkP+u+3ZPoGdZn/KmyVh5icUg3bwUYkxVUr
         Mj/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=snFBMQ0JIvbHdRFdtX5/O2rzeZvOsFxtzSCsMd7eU1k=;
        fh=YQZzxqDLz/zaM3dLtaKENQe6KqObW1ibknEmp2e3lfk=;
        b=QMcxX4V/gR0WJhgOB+2IngMbRWwD/WIcb+suJ9IN6fZknMU9IDwIYuUQXm2OY+kJvV
         fPDR477IGcpKRPOstcQ6Aa7Zmefm2U3h/xj2EsoTt/8Jmi8JA9hoW5qDDCoQCgzrUf6r
         aJpmLDkkWV5lWf7By5UYqrkW3dzWn5xI3YFd1VRoYvNZ4EUZsCA1V1vxK0pcQ/o19AzZ
         jw4lk98gvdI3e9Q/fihANipMxOk4raNHeMFzaCzmInlEg5tRrG/pKNg0WWJKOCoWtui/
         k5cZvm/nnadpPR3fyFcHWIq7kIb467tk+dBTYmNYtIX0mJhAhvXRtKcQaqNDEScv9dlF
         4Opw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=iIyqHUmB;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761764822; x=1762369622; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=snFBMQ0JIvbHdRFdtX5/O2rzeZvOsFxtzSCsMd7eU1k=;
        b=kvB7pH0ajZvNg3JWE9aseEqsV6jVDyUELSLfHTmghZeOYO8mUjGJQM+bvVHWqFv9ET
         Du3yqoL1scFhjui+693q+q7fxr548NuYTZMfMmqC5uMg35UnputjcHrFPQrjsX2wJbOK
         4k4LfYKYYuFXKchrGoHY69T4ZI8BYQaCd2t9VHCkhRSrZPS4kRbuLhDE7qJXgCUDwAw3
         bpjQlzKxOn61cF18lpDt31iV5KHEAz83b/ba1l8G1i+SNfSebEmGE0Sk6tB7l1+eDIhf
         H/4AEJoePYio8KqjjKCgKc6RFgLKFvXWRVHP5l5hfSCi4ul2shEZaTOFRs+046ZoASWr
         FVGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761764822; x=1762369622;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=snFBMQ0JIvbHdRFdtX5/O2rzeZvOsFxtzSCsMd7eU1k=;
        b=wXvCJ9Iukv/q7QrI91dcxYj9EXf3hPtidIW33/y0h5M98kysGolpT6xUP1SiAWXsdr
         CfXYyVHDQ78H5EhNJ1DKZtemj/A+9+x02KKAAMkv7eX1CExvtI6Gk75DU6iWdy8mHyqh
         068o6ylxtY9PnCeAir5VXMQ5/a7HHy7mXbZhp36af/YUdkXOCe1XJAbrC99KqSPjePJ3
         Y1+SkEkEUz9T5iudusLtoX4qU+QQWn+mu6XF9s7rfTTANNnZStXk9cqS8Tg4SOt1Li4F
         Z7UvlPQePa3lsGaxB+idvEqHYXCA6+rwIC48FOwGAjU+iErPIcGm2M1Hwae/MGcFLEcZ
         sbKQ==
X-Forwarded-Encrypted: i=2; AJvYcCX7Ml2Il4ijL5gqt9hK6xHgz3dGCnGdTQA4ywB33sEFANFbQfryJszhfMJzf80G/jbw5KZ02w==@lfdr.de
X-Gm-Message-State: AOJu0Yw135Xa/3N9OHAYkVwSclRMZG0Pdk/FB2ffltgY71CAxrLFYcEW
	ZSY/OBGR1srEL69sa9ZTZHDDZ8osGjnHXnYhjzKw1X9AIdrmxb51AV2P
X-Google-Smtp-Source: AGHT+IGnDJSxg7W7h8qT44cH83zg6W1LeC3wMc505EY9F8m/+415TsBbfWXIFCi95YNywFs056u9UQ==
X-Received: by 2002:a17:902:d4c1:b0:25d:d848:1cca with SMTP id d9443c01a7336-294deec64b3mr49590925ad.35.1761764821658;
        Wed, 29 Oct 2025 12:07:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Y0AoduB0lMuFWrGKcXdO4qwKD5Pbp2CYXRtwQmabVUKA=="
Received: by 2002:a17:902:744b:b0:293:57b:aae9 with SMTP id
 d9443c01a7336-294edbe9d67ls957625ad.1.-pod-prod-02-us; Wed, 29 Oct 2025
 12:07:00 -0700 (PDT)
X-Received: by 2002:a17:902:ebc7:b0:294:cc1d:e2b6 with SMTP id d9443c01a7336-294def36b76mr55228485ad.59.1761764820276;
        Wed, 29 Oct 2025 12:07:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761764820; cv=none;
        d=google.com; s=arc-20240605;
        b=kUm10nEc26FwWw1mKR907Cp9LrDZ2zfcLilA5MfMVGy6L8JJDXA1r5UzYv+/KHxCiQ
         R6uF3yZq2pQPYlatZC9RnuOPax0flq+UFVbmntdDlLzyTtM8cgE0/EP231H7KImpKkLM
         GP1SQ7DQZnePGBr0/bgnuQAZ+o/seywcIb4zXVBF6IF/A8iLj96bRh1xl+CiOOZIzaIe
         DfiVuCaMSJL4ro2oEp98iiOOFx6KieDHOL2rn93Y9y7Gxtu8f8nRFWXtwPMHSH11qU4l
         X2kj2jiMAsxjJe1Q7fbD+DZl327sV6o3tir1HFzl9X+gzBrVrs+zlTHNbJ2NWsnvwgKj
         WAGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=UuVBFIvAqVGiw6UOZ0Oq2LH/B7F2B7f/ik0cOvmOtjs=;
        fh=F9cNJe7/uLron8lsbb2s7B83ncoMqIuz1w+0GaoUZzI=;
        b=byQ/JZKoKAUd0MwSg716H21IPk3Bs14Yf6vkAeob93RSwVauyBlVRlHBcoGILk6Kue
         Fk2aSrW7cZo4ufXnCPy3QNpRWKOG2vNkZlzuQwRGQxr6nUe1cJ9F3x7k5JDXX+UHrOrT
         axUOj2Q1gFK/+rT6mR9/Z4aXGrN6twXmrPzV+QZYqJtP4gB4MUsUgMYQz4zjUjRdrMAy
         G3k6fTVhYKKpgEHmiKx8K54Cl3cwlx+B2nk9GwcwmKDSYi+k5BQ7SkI/beZhV9mgYNNR
         XWaNeBkmUNk3fB5WomhSyt8ExoUuxCfws3lqNE+dSB8oURnX0hQyExlyT2xirMjWDTCh
         PtKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=iIyqHUmB;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24418.protonmail.ch (mail-24418.protonmail.ch. [109.224.244.18])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2949a7d74a5si7645395ad.1.2025.10.29.12.07.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 12:07:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) client-ip=109.224.244.18;
Date: Wed, 29 Oct 2025 19:06:49 +0000
To: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, m.wieczorretman@pm.me
Subject: [PATCH v6 05/18] kasan: Fix inline mode for x86 tag-based mode
Message-ID: <8681ee6683b1c65a1d5d65f21c66e63378806ba0.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1761763681.git.m.wieczorretman@pm.me>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 57ed454739a234eef863007c4125f42148d9fdbb
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=iIyqHUmB;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

The LLVM compiler uses hwasan-instrument-with-calls parameter to setup
inline or outline mode in tag-based KASAN. If zeroed, it means the
instrumentation implementation will be pasted into each relevant
location along with KASAN related constants during compilation. If set
to one all function instrumentation will be done with function calls
instead.

The default hwasan-instrument-with-calls value for the x86 architecture
in the compiler is "1", which is not true for other architectures.
Because of this, enabling inline mode in software tag-based KASAN
doesn't work on x86 as the kernel script doesn't zero out the parameter
and always sets up the outline mode.

Explicitly zero out hwasan-instrument-with-calls when enabling inline
mode in tag-based KASAN.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
---
Changelog v6:
- Add Andrey's Reviewed-by tag.

Changelog v3:
- Add this patch to the series.

 scripts/Makefile.kasan | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 0ba2aac3b8dc..e485814df3e9 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -76,8 +76,11 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress
 RUSTFLAGS_KASAN := -Zsanitizer=kernel-hwaddress \
 		   -Zsanitizer-recover=kernel-hwaddress
 
+# LLVM sets hwasan-instrument-with-calls to 1 on x86 by default. Set it to 0
+# when inline mode is enabled.
 ifdef CONFIG_KASAN_INLINE
 	kasan_params += hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET)
+	kasan_params += hwasan-instrument-with-calls=0
 else
 	kasan_params += hwasan-instrument-with-calls=1
 endif
-- 
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8681ee6683b1c65a1d5d65f21c66e63378806ba0.1761763681.git.m.wieczorretman%40pm.me.
