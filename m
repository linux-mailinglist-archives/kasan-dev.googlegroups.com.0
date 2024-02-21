Return-Path: <kasan-dev+bncBC7OD3FKWUERBTVD3GXAMGQEGENRS6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FA0B85E76A
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:04 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-5cfc2041cdfsf4921306a12.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544463; cv=pass;
        d=google.com; s=arc-20160816;
        b=OUZqNxDd+mdVoxiQOTBY63qaG6RAK8XTCQ61mYwmjrF5qY7gyMjKJRw2dtKZi4rfN1
         upuT2cGn3HbyiAo+zbkqp6m4HtKcnhRZuvle/662/pq9EJXb3wWtinUdHUcn5uxSBsYi
         6Of0/fD0GZNtefyYSkY4qBAEYS+Y7YYJVa6AQ1CpCwjBBdqzuCuzx7bx81Ct3oFUDwL6
         3G4WVQ+kOoIUyR4/OO/a0d/7EESqJ8RFTdW8WuSZmRaZ657Em9V2jiEKxcLw3l9XEpaZ
         TEd5NjmNPGnE2kEECACuQkqHBXGiQObPq1w6XG2u2IiFBjarSbHfHiX3e5ZZ5x9e4JTg
         D2Tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Fs2OfvRJPQfn98uKXzyccJtRmLvP2QgNIVddJK8dx1Y=;
        fh=Z/sXRjUzjwG63cDbtFAcRumsc8rxOE4SNy2gXOoslFQ=;
        b=e/0+VclDGoKntl/6rVVYbhOT/uQt8ALBI5kmECd7x+micTEoCCn2iaJrZrmGN0U3xF
         FPdkII37iAGL3gnQVzVoZfJjGSTn8SZz66zUZZMLebL7BWHlrTUpzYlC9613yQbDC+9u
         d1T5QAiSwhz4j1znVttFpWIWJsVTA1Ufmuc7AAOSl+Xr/FroiBrL4Wnes8KrdXD3wUxr
         3NWspDM3FadAoTfAhCfoHnuVarlNQcvaVi1E8NVmFrz1SuGru1USHzPd1hCfxlE+p0U+
         hBOj9wGywVIuilRK4HCQjy5KUWVk2a1742ZLFb32PUcYQGcnYV6OiN0q2Qb2tuaMWzrd
         O2Og==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=m5Vu7N8N;
       spf=pass (google.com: domain of 3zfhwzqykcf0xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3zFHWZQYKCf0xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544463; x=1709149263; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Fs2OfvRJPQfn98uKXzyccJtRmLvP2QgNIVddJK8dx1Y=;
        b=Pzel1NNsq8ZQxkEjjfm3V+9e3LCtAHQvDdD4l09tJIGPkp4U2DuBoPLjLAI82lFgHc
         xr2udPs4bAvo/h5uVoKSZ6pr1gt4aCYaxIDk3wGsJ3uMZ2lGRMD2aCkclqP/jCl06ODS
         BQ96z1OiJjXdMlUsD5x0/6iiNgditkNMsUCVbKNvMENHj2Ok/1PV8399/bbhtJdIrHhi
         ShoCzznUkJhAgqLnIkFp/CWNqQOqpAkPT4qkx/gq56kcff8YYebqwO8EL1H47soW5rnl
         sRn8qTJ0x6V3pi1gWN6zzuSEBLMFayNqJeLolPu6/rxf+ThpfOvWQMmk5WtEWoRFr8Eg
         KVjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544463; x=1709149263;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Fs2OfvRJPQfn98uKXzyccJtRmLvP2QgNIVddJK8dx1Y=;
        b=pqtSDyjPE+uDO2YRG2i7ZrFhgxjAyMZ6Gye0L+waA4A0htR8iwixnx8hfg/0I3tJfR
         VBBYU7YBUduLyY+nj4O7B6reyfEx+T9ZzBnHWszF2JhAw4d97FtDM+SofV6dDyQpzoIX
         oW+qnsY0eoiDgJAyLBVhyASJUNopDRI1WAUvTk1DlxzKbqOYahZnTMtYqYeudY1fT/h8
         VKzB+e5AXtT39GTb+ywVwAnXWsog8jQ3HQspFsVDYtbBFZUZA0koqs+qlOv1y6brshpR
         yngj9u9m8PEDh952HF+R2GJtOL502lrg3rP4N76XQLprBgJjnkBWTjPGQ3q5rkYhjsN8
         IWSw==
X-Forwarded-Encrypted: i=2; AJvYcCWcl/x2BXDkm8okPUD+SWYAQytMJ+ESjWlkbGLWizwX9+naT20P80f+mznXswmQtDt11P96hGZMmMyNQQmJsvBjQgMhT96m3Q==
X-Gm-Message-State: AOJu0Yw+gl38Kob9F2HLDcw9f6Ed/9PNoXFw9f3p3TjSRvSJo+j3nZOD
	j7zDRF1FCRu2yUK2YAsHtyJcRKSHV4upeZ8WTa/vf6i7fw4Fv8U1
X-Google-Smtp-Source: AGHT+IFJpFMnSCRYq5+dwggijm0hCS9/9hVKDOT3a2MgwH9w9U1ygtrrPj9K72f9ilsjX356AforLg==
X-Received: by 2002:a05:6a20:94c4:b0:19c:6877:9943 with SMTP id ht4-20020a056a2094c400b0019c68779943mr18598775pzb.41.1708544462962;
        Wed, 21 Feb 2024 11:41:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b944:b0:299:6474:6222 with SMTP id
 f4-20020a17090ab94400b0029964746222ls1705692pjw.2.-pod-prod-04-us; Wed, 21
 Feb 2024 11:41:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVj2OcBFU0vgPl2E5uTlbt9Z3wMWFb7sQalMThCaMbtTHoqaR8GuFjgqjirQ8oQxKCQMSheVHrlYOqeK/IQpwJUEsDd9fq/+bXr1w==
X-Received: by 2002:a17:90b:164a:b0:299:5913:db15 with SMTP id il10-20020a17090b164a00b002995913db15mr9432055pjb.29.1708544461870;
        Wed, 21 Feb 2024 11:41:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544461; cv=none;
        d=google.com; s=arc-20160816;
        b=n8yeBX0pddT1Qy0lHmPkMiH8zzpXUzW8YL2ZWYRJdY8E28UEjn2/ApBT8qPTP67bq4
         xlTKlMGstgfZ09itpaIu40kVcyPuVJeeFtsl7Z0B/urakTL64KCtp+t2uKtAbsEpbuJU
         d2pIFK7mCeVTFE2tJPNcgOfkWrZEuPqjzaMCB/EEu1Wlmobp0KsqEGnCtTRDZ0/+0p/X
         BqadBcLuXi5jWfPed4qwLefQRMMx6UZs8oskmbDJSrJIg4PQhKmUb1ibPic2XnPzdV0F
         epRU2fMFeiYxRhWvigEDIj2NGYhVY5rlF79IpA0ojK2LouF+IXoYPXy0e6QQ5uwJSbPs
         Wu8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=eOix7cIZ9OpjtRmnOCb5oo8qhMGRBISTNpiHk2ice5Y=;
        fh=qV9Q7wsTtylRbtwQtgd322Qu370wfF5iP1RG/3gzcJw=;
        b=lIbPo+ekQuQivRLUB6trz6QO5iec9KYGen0tqrJ2pnL4jPZbQnrVIo0ObAyxtzcXvK
         z/OeXUWjag39yCvpvPHKGXxYhzRPM+UR+DRl81wvdedwftUCWxZ57JjqOP7E59YJ4r3l
         nXfeEe2IIcWvf13gj9XkXm1CW0F8c5/glijsPKcDhgKXjW0d/0fvu51VdfaqE/V9Qc6K
         fgKOPjnMX59SzdgIvAw7gTljUyhGGTDWiFXL5bKyoqAlmWtnPabYBbslIuBir4htKHG/
         Ba3g3+MyrD9Maa4eGryXRevzAXsO93un6m9POGPJDOcThkNRo2gRolh6gSZ03bvv6/g5
         aJgg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=m5Vu7N8N;
       spf=pass (google.com: domain of 3zfhwzqykcf0xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3zFHWZQYKCf0xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id q4-20020a17090ad38400b002993c104736si30347pju.0.2024.02.21.11.41.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zfhwzqykcf0xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dc743cc50a6so9721561276.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:01 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW6UdoaCyIvG1GASO/zkbeGpqGMgHWt2lwKCty0N1AcfdfZZ5BG9m9QPd365R3AQaG5q1JjQkZkxE98LzgFVktEtvZ+hd9xaZDoYw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a05:6902:120b:b0:dbe:d0a9:2be8 with SMTP id
 s11-20020a056902120b00b00dbed0a92be8mr7992ybu.0.1708544460699; Wed, 21 Feb
 2024 11:41:00 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:15 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-3-surenb@google.com>
Subject: [PATCH v4 02/36] asm-generic/io.h: Kill vmalloc.h dependency
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
 header.i=@google.com header.s=20230601 header.b=m5Vu7N8N;       spf=pass
 (google.com: domain of 3zfhwzqykcf0xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3zFHWZQYKCf0xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
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

Needed to avoid a new circular dependency with the memory allocation
profiling series.

Naturally, a whole bunch of files needed to include vmalloc.h that were
previously getting it implicitly.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 include/asm-generic/io.h | 1 -
 1 file changed, 1 deletion(-)

diff --git a/include/asm-generic/io.h b/include/asm-generic/io.h
index bac63e874c7b..c27313414a82 100644
--- a/include/asm-generic/io.h
+++ b/include/asm-generic/io.h
@@ -991,7 +991,6 @@ static inline void iowrite64_rep(volatile void __iomem *addr,
 
 #ifdef __KERNEL__
 
-#include <linux/vmalloc.h>
 #define __io_virt(x) ((void __force *)(x))
 
 /*
-- 
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-3-surenb%40google.com.
