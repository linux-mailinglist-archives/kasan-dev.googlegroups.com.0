Return-Path: <kasan-dev+bncBC7OD3FKWUERBF5E3GXAMGQECKST3GQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 84D6F85E7A1
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:42:16 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-36531d770d1sf35534685ab.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:42:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544535; cv=pass;
        d=google.com; s=arc-20160816;
        b=dXK4vAZzyk8PnVPQ/5Ct9bNBGqZWaaOzWoJnL9n3MoULJLCIcXmkIiMwpG6ZpSUDKP
         sjP8vNL2VbkewiHYkHpvjXHSEi13CCH/NQ01kxrdGLIUL3PESVP4Em7JmWrafV2NXmOg
         kpeno7CkiJdsr1Y0EMAdLodFlHWxqmioHu1z44khXBSJ7+zXl3S68yBHsNqPp3O+GsJK
         N7A2dfejc0/VU75La2f+szH3He9tysyPFmtLCAuYnST0h/VP9xsNP9ZmFdrfoEj0sP/J
         hfEq/v4eC1vt3LDUV3WJSEHoeCAQ8wCFEDBE1gxmX/dnjCiqvCs027Wk+fnnusG56fVL
         dtjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=fcBLxK+y1yTqCIrHsh3elbQameYU1haG+saz+1v/vtE=;
        fh=XWYIbXPdRkFZZQ/EzJlj/prTh62YFX1qEgGAn1bluuY=;
        b=qOm0vxzbEKajnY+G7SC7nkGaWd9tKlz7hTP9mANwP82O8cTN7Bfv+ZRtbEJLiT5O9N
         apYayE6Z4ImEFZuR2gt3p58KMxXKZy/u83y1RKT2VJUs/tGgCSotjzPySxEfKRqmW+qS
         27os9u1JxmZr5pqAaQnJnBZZbVzOxYysaVMF4Th+D+L7z/3QrofJg8J3fw4YDcaRqusD
         p9Z58vHfa2uV5kQlT98sifbrpPcMg3cI0jY3oe7mVg4OWyaJ1q7lg7Tw1Kf6/WIV5EdN
         h+tUZ+B6XqDYCzR3uEjcwS5Q5T2BLDHuJ1GvisSDePdI+b2NfunY34zBsLRkfyg57TLM
         X+HQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=q77vtRkJ;
       spf=pass (google.com: domain of 3fvlwzqykcug241oxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3FVLWZQYKCUg241oxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544535; x=1709149335; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=fcBLxK+y1yTqCIrHsh3elbQameYU1haG+saz+1v/vtE=;
        b=jRP4P5FHsiFJfyUP/tBOeEmQrSavSAsAgUlUic5zfMwV24bUQ4LpjcsYFp1ZSBamxT
         iqHkaBudVvbWiu9uybOqTzADfUn6ekOOeWPl2Ku1gOThwaLQ573S0KJ5WB2Sd810DYB/
         MnviIMa/6COTyO7PcH/wK/g52CS7WFEHaFBc3a4zMBin9/hsMnIUJ72HoPeCoZ8hzy9W
         2g2hpbqSVZjwV9drM/hLWtF1Dgho3p3/jPpM00Cyffj5I5RTlJuJs3xW5AsHT0tZ6YKP
         FR4DOTcLqz/B7DIrQb8VBbpRYOoBM4wmChfRYb30v6XAotcMdXh8D7OMI7D9xo/DXvpF
         eaAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544535; x=1709149335;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fcBLxK+y1yTqCIrHsh3elbQameYU1haG+saz+1v/vtE=;
        b=NNADFeFgdsAXts5MoSbqwqLsiNNeRhThczdhWQkumtBPuIqeAxkK3L4jDF0ahP378m
         nt+8cZJCHhYsnmAPXlBK6vsyHkEqjfoDgdLVENHMvq2yTPPNxt1QOnNrRMzvj8vSgBaZ
         M+eW8H/gnPopQLBvxg5Z11+56tGUT4XJvrdW+oBg4Dg/tiPPGFxryWBgdeRrQUADBfO7
         Uzc2J01Toyxo6E4VzqJoqK3NCMs/+OKY8Gp8zcwzo6VVRgvCKwMW0qb7Qa767w05uVci
         NiUaFv1CW8XndhdVT3goF2aH4CGLvYk034aJTA5tqA/uYippVfD1gUJPt1HhXDavBinu
         g+VQ==
X-Forwarded-Encrypted: i=2; AJvYcCXW6EFNzHUE9Rew5ox0OEyp2zRUiCU/hIFGLLdr7ls4FjOBW43SykRTTSUfxBJxtEjQ/0Ibrofm6KXjnHNdCZwPeNYPJZLPFQ==
X-Gm-Message-State: AOJu0YxrpQ27OUjliw6QLQbduW3U4/71G4HTbFdVgharHkAEzpSyYhl2
	FKD1Jq1oC3eMvF7dQCNEv7lyDGKbVfuh0XfYheHyh6NqGMCgKHpE
X-Google-Smtp-Source: AGHT+IFADbAln/IguIt+4oCo1FjuQeEGqn4Nl1ueDrpIA7tVZEDFnywK+mRY8fxcYNy/LWc5qlLLKw==
X-Received: by 2002:a92:cb09:0:b0:363:b14f:a040 with SMTP id s9-20020a92cb09000000b00363b14fa040mr18811562ilo.1.1708544535406;
        Wed, 21 Feb 2024 11:42:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:5c4:b0:363:9091:91b5 with SMTP id
 l4-20020a056e0205c400b00363909191b5ls2471914ils.2.-pod-prod-02-us; Wed, 21
 Feb 2024 11:42:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXitEm0fFasu95zTc47BtYUsSO3/ndYVLtJOq+NfwXx7XvtMxK0oxbWhc8cxVGXcehhooIGXUuHYhipJRurmDR80SS3ZceflAb81w==
X-Received: by 2002:a5d:9c0b:0:b0:7c4:61e7:9d77 with SMTP id 11-20020a5d9c0b000000b007c461e79d77mr22943332ioe.19.1708544534633;
        Wed, 21 Feb 2024 11:42:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544534; cv=none;
        d=google.com; s=arc-20160816;
        b=UZjLE7sKAU2jZ40lnG/owy6efUy+MQNy+2Uf78vCqtRdepNnriI/iQFSVYPZkrr1+Z
         qgm67X1ukJsI0GmWzU5gC77cRekODW3sahsPwNhHQqi8fCKIL4tSYKHBovgtD34YX5xA
         j9rwb1qbc9Qn2/xqFs6nTp1AqGzmw2KmRjRC8v1vFRNXgbizzabbEYTJJjNo00AFb/ca
         jk90wCQNYy3jox1oipmDfm52EHHlUr3D62Afa/eNUt9Xhoyms1dBb59EXCoSzr+9vL5D
         g+hopkGC/EHnvj7uDpb8tG11nnQQ2qMvsmIlOKOKYbUB9gc2qN7DJUWoeQb9SGtnsqVw
         eKaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=8ETkntKf5Z8TKkoIJeAz1krTkKQJvX5Zd0TKA8iBrrk=;
        fh=traxZvDNM40uWndUyXGvQvX7ZujZEMYqaI028OiB/0I=;
        b=gS2n7JT1RFoQ8z93rAevTVbZjEpZnWH4YCUAg1K3a90ivrJdN74148mEnHbBzmTSbD
         v0PtRayLb97pzLNOY/lhtVxQdWTzKrK6+4Hj2QXUqLLNhxP/naVczh9a+JZ1HzU/0WsF
         xSBz9GTqWEwGhTZXpo4/L21A0L+sXcpfPSlqp+nSHrnkqJuZnn4rz2we0j9UvjyoIotV
         iqPLNJJP8CE4ei5TePIbuZs/UF0EkQw5nVWDkziNqg9qj9Ap08S3nl6B1RwwzrqBHivj
         c9KUUq1AJ7DF6A54XYnZ5bNdtsudugTI+DYqqVlASaWhamkcbEsjXeMEOZBXZWfnlQPn
         IemQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=q77vtRkJ;
       spf=pass (google.com: domain of 3fvlwzqykcug241oxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3FVLWZQYKCUg241oxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id y10-20020a02730a000000b00473fb8430c0si1285650jab.7.2024.02.21.11.42.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:42:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fvlwzqykcug241oxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dc6b267bf11so6915428276.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:42:14 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUGoNSPqIoJsEpgQoasugZIRaBTtBLWPObPdTRDZGV9xDd3nIkRehkSwbm/EBCtQ5yuY+MDKag39Yknn0bWRHrhBWEs4BTBNnqFZA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a25:844b:0:b0:dc6:ebd4:cca2 with SMTP id
 r11-20020a25844b000000b00dc6ebd4cca2mr14813ybm.11.1708544533985; Wed, 21 Feb
 2024 11:42:13 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:48 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-36-surenb@google.com>
Subject: [PATCH v4 35/36] MAINTAINERS: Add entries for code tagging and memory
 allocation profiling
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
 header.i=@google.com header.s=20230601 header.b=q77vtRkJ;       spf=pass
 (google.com: domain of 3fvlwzqykcug241oxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3FVLWZQYKCUg241oxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--surenb.bounces.google.com;
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

The new code & libraries added are being maintained - mark them as such.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Kees Cook <keescook@chromium.org>
---
 MAINTAINERS | 17 +++++++++++++++++
 1 file changed, 17 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 9ed4d3868539..4f131872da27 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -5210,6 +5210,13 @@ S:	Supported
 F:	Documentation/process/code-of-conduct-interpretation.rst
 F:	Documentation/process/code-of-conduct.rst
 
+CODE TAGGING
+M:	Suren Baghdasaryan <surenb@google.com>
+M:	Kent Overstreet <kent.overstreet@linux.dev>
+S:	Maintained
+F:	include/linux/codetag.h
+F:	lib/codetag.c
+
 COMEDI DRIVERS
 M:	Ian Abbott <abbotti@mev.co.uk>
 M:	H Hartley Sweeten <hsweeten@visionengravers.com>
@@ -14061,6 +14068,16 @@ F:	mm/memblock.c
 F:	mm/mm_init.c
 F:	tools/testing/memblock/
 
+MEMORY ALLOCATION PROFILING
+M:	Suren Baghdasaryan <surenb@google.com>
+M:	Kent Overstreet <kent.overstreet@linux.dev>
+L:	linux-mm@kvack.org
+S:	Maintained
+F:	include/linux/alloc_tag.h
+F:	include/linux/codetag_ctx.h
+F:	lib/alloc_tag.c
+F:	lib/pgalloc_tag.c
+
 MEMORY CONTROLLER DRIVERS
 M:	Krzysztof Kozlowski <krzysztof.kozlowski@linaro.org>
 L:	linux-kernel@vger.kernel.org
-- 
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-36-surenb%40google.com.
