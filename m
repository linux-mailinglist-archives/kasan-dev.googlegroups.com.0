Return-Path: <kasan-dev+bncBC7OBJGL2MHBBX6FWXTQKGQEBAM2J2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C1522CC13
	for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2019 18:33:37 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id y1sf13718642plr.13
        for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2019 09:33:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559061215; cv=pass;
        d=google.com; s=arc-20160816;
        b=I+RSqGcVH5bD6MA4bPcfn2Dum/HlfLEXNVw9+hmT27635h26F6wfnykXzL0EFdEZlr
         XFfMiCfgC1lA3XoM2JTfGcBvkn4U8Bq3/EeXAtDdN1jgRn5TOaZGmRNnpteger1bCOEq
         +NWi5uyBq2KzqKYKgrT+4CjBmmwyK92NSHof9XhZHdLyGtxwJqxjRiQ3Wgp1t9VhjN0f
         zOgpw6YB1fmEkLfrKhc1awzpBjWBsp+Oyh4UYqLqwzc3QPf6GpFSbkXeS1cznHRM/eV4
         R0BzHcfH3RypLGUZdbdywsScZf5rZ2vsi8Qtx9RYoSFv5eY2sq9B10VshNFiv8ACnyk9
         wVbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=n2Hb3z1oO98uCVhbiYN980PzedXG3GEU87bjKLWn04I=;
        b=S0Nl58SpaSxfvWIIfcQA6oNqsz8NrwT8QDhWJo23/cn0q/H8/4l/hSI0i176UI8oFQ
         H4+7qhI6Ah3qbyhOgXRVYKhmrEjODvbYSA7fssZ4szPaEJdxmJwSzEtSK38c+zauz34R
         lbi7cRfFC4Ghv1uVVzS7EHrD0zFEfVcNuewNLHoaJhafwLMmbYoenvB9sitL7BIARkPa
         aYTxHBeffLtF/yEYtqatF/iC/7YsBkkxmnE9rWaJMJzvrQ/6iD5rGVwoK9VkT+Sgl+Jt
         Q4bj69eZkEtFMDeRvtbuGINPYDdtg36S/VlYtdACj6WxO0kYflO3eEOIwJydcFZKOHj7
         0K6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=U5odcy97;
       spf=pass (google.com: domain of 33mltxaukcucnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=33mLtXAUKCUcnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n2Hb3z1oO98uCVhbiYN980PzedXG3GEU87bjKLWn04I=;
        b=hkUJ4egRG/SkWNBjSao4o6VGd+kWyrYESrlpt8IlY7xzHNn+WVoDM6pJmTFkWm0Jxw
         eYJA7dUrJJyETcWE0umY3DDfTm7f6/aV5jnd1HHZOTayNePx8WpZEYSd8kqzU6vJimkS
         S/4XMi1TdLvju0xpFMXVi4lcra1cjo77Ipf8DQpbiS/X0FEpYzNz0VAyaRNaoeJErJ3u
         B3xpgxCo0nxXgbHnWNCZKIriiBEnzt+DSJHcbD9RZFmyM/8+DWqzI8dfkLENwR09dPBw
         bx3T/mesdJRUtUu+GizI/Zi5p8mrgnHq3dOxbGCzDLCS8uJVSu8JqzZCZG5BXH3yAkaP
         GieQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n2Hb3z1oO98uCVhbiYN980PzedXG3GEU87bjKLWn04I=;
        b=IpL+OI/VhwzlrEFEtAxjQJWwKpy44wP0enKxCATtXSE8mrCbvqalxchxCUUw+yrYxN
         1NLlVz/MZMQuYntalLiAwew5EFpLC6NXg+InhAagpt5TKYlXa0Um20oEy6alHbeCkFZT
         mOOBODHgTEDW2mGLK6FjWVPoG4rt2QhOAEN7IrM9njGlgYmSebkT8RF0ELFo8nkjlsMd
         u9+i3uIZFd2fkAE6MZO32kjnL4ofQca2mNav+n1kZYtNWFJ1yq2xyBUjKWI8hEMO/8Pt
         NTyfLdTfK2ZZ1gRXKGTEaUGuUDAh0mPmFHp52a3ITheSEGDeztpWWwNC591MZR1HQQmo
         r6lQ==
X-Gm-Message-State: APjAAAXiUEgfvWCihajmRjqnNFyNkfT/swvzYzpFORJCGRPocuhMb0Ex
	kHKBeD5BVeQosJCI+d+hbGc=
X-Google-Smtp-Source: APXvYqyUzsBb54OARJv4kaFUtdx74tu4cOSUSlfVcWIfuSfTx7dg+zQdCzxMDw9el2rQIZJpE7IfTQ==
X-Received: by 2002:a17:90a:c503:: with SMTP id k3mr7108658pjt.46.1559061215739;
        Tue, 28 May 2019 09:33:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a9:: with SMTP id a38ls1311279pla.5.gmail; Tue, 28
 May 2019 09:33:35 -0700 (PDT)
X-Received: by 2002:a17:90a:8c90:: with SMTP id b16mr7149551pjo.85.1559061215404;
        Tue, 28 May 2019 09:33:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559061215; cv=none;
        d=google.com; s=arc-20160816;
        b=MYFkanIcoUQmOv6k3pfrIkRCYCUxfL4U8onXiu4TIj1vy4tT8f8bv84ywQYgjsqUbW
         YKR6jz7vSTLPaH8mhSWq5lFq0KzydQFRso6K9rhwFQCFek0Lr/X5lyErh0lS8zTHrDU2
         D8ctf0GS3xpmlGQK0tMwAWCw95FkABc2XM4VfvjJ2ia8Nb5Z8V8Ym6jSDwebsi6FH2yv
         7UfaqPJfSJBgs18AWPUpj60xkaJUvIHV3iLATRAN49+pyeeGC5arQzt73oMVkrTiDXvS
         80Q8T7KDYSQmwOSC1VEmXJH1yNpXAIZST8dhl/3npEZ8pxqRM4gDEWtnx+97JMeKQwFp
         kJew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ekpV16BsEuFUmwpAG23aREMsNr/hn6GV4TCSg0P4aJ0=;
        b=dUS5PP16SYebWL8xrdTEyqelGuXuAoNvU8C+ffToYfgO6LFK509ZfSVIpetJBH8aj+
         RttW83ZwEisDyFzbvEhXnZq3PtV8Pz6Wdyw93pilOifXCcAqmrmGmSRroFbUbotLrBZF
         Evk7GrBNBV67dq/GufB6qoVk76lMfc4w7HBgVRm8LtG/Nq+zWQNtRG5VEnkPAiJEu8Sk
         p/CHvGEIiDHtyni0iAhht/TlbMwsEM+oUWBbkhwlFGjZcwuMLvOWpdWdZxPTRvS3/87A
         CKNO7Da5BJtwfe+tovSgRMjtH8HwcElJD8pP27SVEhKzUkHzzObBf9T4KMCMmJpQvjQK
         A1+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=U5odcy97;
       spf=pass (google.com: domain of 33mltxaukcucnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=33mLtXAUKCUcnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id z6si404073pgv.0.2019.05.28.09.33.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 May 2019 09:33:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 33mltxaukcucnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id c4so28599712qkd.16
        for <kasan-dev@googlegroups.com>; Tue, 28 May 2019 09:33:35 -0700 (PDT)
X-Received: by 2002:a37:ad12:: with SMTP id f18mr5399903qkm.3.1559061214532;
 Tue, 28 May 2019 09:33:34 -0700 (PDT)
Date: Tue, 28 May 2019 18:32:57 +0200
In-Reply-To: <20190528163258.260144-1-elver@google.com>
Message-Id: <20190528163258.260144-2-elver@google.com>
Mime-Version: 1.0
References: <20190528163258.260144-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.rc1.257.g3120a18244-goog
Subject: [PATCH 2/3] tools/objtool: add kasan_check_* to uaccess whitelist
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org, aryabinin@virtuozzo.com, dvyukov@google.com, 
	glider@google.com, andreyknvl@google.com
Cc: corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	hpa@zytor.com, x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=U5odcy97;       spf=pass
 (google.com: domain of 33mltxaukcucnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=33mLtXAUKCUcnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

This is a pre-requisite for enabling bitops instrumentation. Some bitops
may safely be used with instrumentation in uaccess regions.

For example, on x86, `test_bit` is used to test a CPU-feature in a
uaccess region:   arch/x86/ia32/ia32_signal.c:361

Signed-off-by: Marco Elver <elver@google.com>
---
 tools/objtool/check.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 172f99195726..eff0e5209402 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -443,6 +443,8 @@ static void add_ignores(struct objtool_file *file)
 static const char *uaccess_safe_builtin[] = {
 	/* KASAN */
 	"kasan_report",
+	"kasan_check_read",
+	"kasan_check_write",
 	"check_memory_region",
 	/* KASAN out-of-line */
 	"__asan_loadN_noabort",
-- 
2.22.0.rc1.257.g3120a18244-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190528163258.260144-2-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
