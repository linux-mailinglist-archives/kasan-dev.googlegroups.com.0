Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVHA6CFAMGQEKR263WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id A321442243C
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 13:00:36 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id n19-20020a509353000000b003dad185759bsf12328235eda.6
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 04:00:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431636; cv=pass;
        d=google.com; s=arc-20160816;
        b=xQpt1jSBioX3PJCIcsmEDJThpG0MDwfrP5Oscc6g1A9jhtGYQnSAFysTnzFw4iYAbl
         TDMezxFqsct+3kyX7+3GYKqcebUkVUhdKEJ6crOoMMoE8cjj8Ssuz47fFSsdhwUo6CrO
         omxV/ZZP8b16NCnXFxbYGhRDy4ZMtErgcdhLzohE8rQ6aGZyPlraciVJH/fmQcHuPfKl
         b9/0ZEcxb/XBnctN6EL97Sp+Mb3HgHHl4x09kF0pOrTGDFZaC8cPvnIx+VR62EptpAgJ
         jEpfOjg4mpjFAlDjyX0Qp7SnIR40pLAKyhhX3xwRD9nvAx0El9ZDx9dVtyGIe03urwuK
         EQEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=facCfyrnCEKS8frd2q5aOWxR7mSs8i6QBEOl8vFBr1c=;
        b=y1kPOD1DnoJIloQHh3F11kEyHoZ/HA+zvUabS67cq3XvBnmQzr/2i0u5djPoCx/5Ou
         PQP3AfEWMt69qu7TY2NqgCMFx4z63dp6xZ+SyD/2QW2qOunwty5ZWBuo9/cst77uqqsj
         vC84SyzqlZsrvmZDKansr8fE8P2Oqs9yUtvNm5e6dy8rtzwYM7AWmMJoOGWv2kZDIpNM
         dcjjUS7QDRNt1wst12QzeK7bFQ+vRrgIHzpyMx0fb5JtvSsVpuBMq7PGrtMXmhmQr3CA
         ZB/s3+PiYcqBJB4zxp/ieNHozmwCYChKVGpArRNlD5bqubkq6rcgBAY8WsXy1Lsu96p9
         nI/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=drtT1iGc;
       spf=pass (google.com: domain of 3ujbcyqukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3UjBcYQUKCTUVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=facCfyrnCEKS8frd2q5aOWxR7mSs8i6QBEOl8vFBr1c=;
        b=aHWZ+bHci6VftHs4Px+VFQxOqgeP1KYTpJ7OteGvRqn9+YnBUHDAqNhyCcs1bunCGg
         iaglkClfW+v6qCk/qTyS01eYnqlvVqbht+ymBCM/fHkKYL0vfdGM/yKauk0wVxBa51x1
         YHSKcojX2zjx5tSGR0APlzV6/GBmB2O+YyEi6I9dlfH9hizscUQQsU/0RhTnCPC6bnDJ
         NyX6QLgASVn5EfO67xoI6lgsf4ZgdekDp66Ca2Ab9LxH+BwOBWsVXmVJXwf7cziQ9lFo
         Rm1E4OAYlKHQjqAo4Y1kqZgBuT7EGLvzzNmsVDISN5ydALgEGLZxQOzDDrlG3POikN0U
         TNZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=facCfyrnCEKS8frd2q5aOWxR7mSs8i6QBEOl8vFBr1c=;
        b=UpcPFN6qKrEDCbVsFpcjRpRleHbz32N7a2ykWk26YUxPML1XX1Ziod+saUx0foRhzx
         aysDDsdMsbnV3x2nX7umywWY6NIiVKUg0y6LEtv30aFPRym+at0SyLul1tdViMjoe53B
         f1USSqnhUKMgbL72oG4aLbxK326UHHR9gpJ6wU3ydMR96/w+AzDYyqD2daADiWJkz/18
         OvwkktGcBwNcQrtkRRztctrcI+8ao7OVbWCLiM3lCwtoJ2qFv0o7N97oWEfF/yjU3RS6
         3+9p4A14bdze5aUEeU95OM1qacCzt/Z42YPJ3ndl3fkH+PEIeCNUKRbC3mzJLk92tT/k
         7H7w==
X-Gm-Message-State: AOAM533S12JjU+YWpxi1suV2eRIAWqk88V9XMqJKKu5nLuPUoLkp6SoU
	eORFNBHIJ2MMByPQvAzAqIg=
X-Google-Smtp-Source: ABdhPJzyr8vx7zWITYTVOcq7hMnyG0yh4v5Eteii/1HtSkyvCs/yCA1j5Q7hiP/wtMsgYkHAvDpu9A==
X-Received: by 2002:a50:bf05:: with SMTP id f5mr25177283edk.156.1633431636411;
        Tue, 05 Oct 2021 04:00:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:b08d:: with SMTP id x13ls9842541ejy.4.gmail; Tue, 05
 Oct 2021 04:00:35 -0700 (PDT)
X-Received: by 2002:a17:906:2a44:: with SMTP id k4mr24185459eje.328.1633431635371;
        Tue, 05 Oct 2021 04:00:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431635; cv=none;
        d=google.com; s=arc-20160816;
        b=Oy60z7PJuXOJkFWOI3uRapoO+SEUc/AEAz8V65beoQ7a1Z4YSxmhWOCCpt9A+DE3XU
         n3HU2B69soSEkzvSENTYqhywJJEhMAO616YT5fQUIWQJed610c6o+IBAaaSiH0D30cK/
         FH1cdKp+skFmLSJ3gCQWBuNM/LXO62aDagiYR9qqhdGmCcPUvGXR+3leWHrjHXdHoW+w
         ++dekKslUokED+6yVEGlMW0sp5DnkOOYlbqUYthhU1ouEKiHaXe81IQAqShEMFfzR3cM
         C9j/1DfjePHS7OT2zqIo3JEy93h/8JY2ogI19tCihCipFHTBLonHV4uC1taG496T76+m
         CkWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=HKI+TnuwkVzGQacqSxDdhV83/KyiTPOZkFDvUOmoq5w=;
        b=RQ3o1Pe2oSujUj89xPkH6jwZMEKHvQcXITj9kYXn0ChWBo15dSwyEPEFmH4u3Zpm0c
         MabD+TpGN1Q3Jg/ml5gmlfjeAyRqDBMlQVXYaSVw5nt9IkM8MkifPOk6kLhf/hPiDzvu
         a9Rk9WiU/bWwnSkACLfJH0tOanRBVhfVzwCTj5RwO92umqyZACVRY/fbGNLX8+xm4wBJ
         W2m4RpDAhMNx9rEVr6bDvU4XAFPENbUUUKLUP5Au5OWvBoefVR8iuhYHn8j+50ghN5j2
         NtdYg8doi4QrSWVWJzmr/xDqKTwBrzor1pE6hcjHc67QaLamBLDVR8g+wfDlX+44LYzz
         SNzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=drtT1iGc;
       spf=pass (google.com: domain of 3ujbcyqukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3UjBcYQUKCTUVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 14si695826edv.4.2021.10.05.04.00.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 04:00:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ujbcyqukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id d13-20020adf9b8d000000b00160a94c235aso1997748wrc.2
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 04:00:35 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:a05:600c:3b26:: with SMTP id
 m38mr554577wms.0.1633431634472; Tue, 05 Oct 2021 04:00:34 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:59:04 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-23-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 22/23] objtool, kcsan: Add memory barrier
 instrumentation to whitelist
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=drtT1iGc;       spf=pass
 (google.com: domain of 3ujbcyqukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3UjBcYQUKCTUVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
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

Adds KCSAN's memory barrier instrumentation to objtool's uaccess
whitelist.

Signed-off-by: Marco Elver <elver@google.com>
---
 tools/objtool/check.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index e5947fbb9e7a..7e8cd3ba5482 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -651,6 +651,10 @@ static const char *uaccess_safe_builtin[] = {
 	"__asan_report_store16_noabort",
 	/* KCSAN */
 	"__kcsan_check_access",
+	"__kcsan_mb",
+	"__kcsan_wmb",
+	"__kcsan_rmb",
+	"__kcsan_release",
 	"kcsan_found_watchpoint",
 	"kcsan_setup_watchpoint",
 	"kcsan_check_scoped_accesses",
-- 
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-23-elver%40google.com.
