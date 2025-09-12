Return-Path: <kasan-dev+bncBD53XBUFWQDBB6PDR7DAMGQE65JPEIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id A2800B548DE
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:12:12 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-b5228e3fee5sf130485a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:12:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757671931; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ya1CcYNTJm6IYeTWRAOQOr+KccjOSEPUCDB8ZxvDvvTpTMpytd0VX6hxvzoFJzg00W
         0FLduFJL5DzeFD4TC9VKbocuWdAda6dmgH6+8sG4TPzZXIaUHrqA/OrrBkn+LBPT5bfC
         OUJl98jE9Mc9I369Gtlr63x+XS+/ePkQJ/IigPZML/Yp/zWSyNBtWcxZHjFWV9qFKir1
         S6TtLHiulsqCn0Njt3ud3lwSbrxS+jBJgFhNmCo32a9kNRbPyfCd3lSzmZy3EY/uihOt
         inwhGtwHp1wYynXbJZsrR8p3tYHcIJ+UV+95c/0Ua8YKe61felG5Gkzdm2lxKoK+fGux
         CenA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=4mdyM+waam0lKjz3G1ZetgGhmU60kunNj6v64mcOJKc=;
        fh=hZpDz04VomZQon7xmYxGWw/Cz6JIypZww9Phv6ZeeXY=;
        b=FBreh4NbQdnqjhc3dBQ4Bkk79uPTpad7exD4nCpSYvh0IxG/w7R2lyQhdsFq9Donww
         5P+NLPBKElACtq9UV1zeJCcKLIOr/Ytvtj/6/Ud35hLzf7Xdg5YA7X2OQaAMY2cQrxGM
         Myjgha+ONZtZXOf3+ExRb3oBOdNw2equIGE0Bjyfnj7RjTnbdGOhicozIfVCK7ZJ9+jx
         L2yTLGAdgsQ5BVpi7l+MZJvcHqitwjKGD1SJUbV0CUMvbfaFzWxbpX+MG3NDoYxf/lsI
         RvEb93kUCEolP16RIyExaypmp9GeDsIPvGuPEFYSxKhKpUfwCkW9fuNkmtgxQ46wcyDl
         3p7A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Bbw8DMj/";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757671931; x=1758276731; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4mdyM+waam0lKjz3G1ZetgGhmU60kunNj6v64mcOJKc=;
        b=M8cHd1l2bChcvhm8e2nCZ95giWzq1HP82mUvL7/lCnQdaMt4jZzfSyHY/8Lykf5N0e
         XR3W3TEIjey2VawkJhFB37yoMcWjk2o6ajSHQmlz6CG5nP5JI/BphRzoIcYZwpcObhDJ
         1MozLVYMXeZvvP//PqYnZSxRAw8HAi+xXjVcOZLi5XRxVXsZUrk7BwEw1t3tt96yJqfY
         7PmcFXJdWC0Wcyy/5JG2yTwwiClSqErrXoo97bFl4oA9gEPsTGGGQEr+mjM7txmVxpVc
         iWBo1zCWdkAfhRoh2UMLkwmX9R7/KwyoILQ3TZbnj6VhUXaxtA+KH3wrvZHeUgienFWM
         cd8w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757671931; x=1758276731; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=4mdyM+waam0lKjz3G1ZetgGhmU60kunNj6v64mcOJKc=;
        b=Q2jYkD1Obu5b/IMOP9rsgJ3/Pupbzn9wzn8HyiL9UcO+mEgrM+duHEzEQYkTdOjz44
         fInZIwJaEbOQ0Xlvjk7g7qjDlKFPBF/Av0k6/cZqaOeQa77S0UTJoUDPaT2QrOGTzj44
         iKy8DXvXjVkWTm12vD8ULOtgPCZpyko7GjRZqD/S1C3IQIMfoAY8CQsO2TBu0XIHz/Ld
         fKs4paVPXbJ9jMovEkXRlHLT9u3KciEwnp+VfPb0CLJkMtP/E7I8b2bopGwX+CtLqYSg
         t1KbNhe25+S3SPOSBqD5qp+lXFX9NcuAKoqFoKEN6tNvOovU5Na+Cge9fnWWeIP3WKNB
         EeEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757671931; x=1758276731;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4mdyM+waam0lKjz3G1ZetgGhmU60kunNj6v64mcOJKc=;
        b=Z91a559dxQvBg/FTTitDNzKVa5HgVNgYnqbIf/ynTSJ0e/rfVfhCU5p08g/KKVYkPY
         o1opDLRy+qg+HI0YIaLMdACFIyatp8U7R0Q9fDPtBOSpXR4ysgPvEfr8bbYGK0VC6mL9
         D3WvqLxmdQhqaByj45+/0Bbu+xMfb97yONq8TVeKNJiT3O0rlJGilpFCP9oY52t3nX0b
         JIPhjq/bhzCHL3qIoqXoxCBog7zo9eBQPTgNBLFMyY1UCd8oEY3bcyC2JQuRcsvBORZ4
         H57y+eMSsHLdU8/GV+8ufJNTcR/To7P26KRA51DXydoxMZ2DjJMIGaNHsu55mpU7N2kr
         98Hg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXrfuosWAjIfOyG02m9MIJC97eZSm7/Tb3012x2hoQnsZtDvrOhGzNUmjQLElbHzcsZu+gMuA==@lfdr.de
X-Gm-Message-State: AOJu0Yxd399IS1PlJ+x7gxt8OVxhhFScGxiCKKZPjoZ7qr5kUi74qyem
	41zZ09oSehFLQllEr4GYVlwhZXEP61gX8p16dB1lcb5jCigbLfN7u1e8
X-Google-Smtp-Source: AGHT+IGhklDPQWk80RR8tfiyOf7BiPyEB206Bn6ZqM54jtT3C+OVb0uc6V/IUgP5RvZXLht8TXPJgA==
X-Received: by 2002:a05:6a00:2d10:b0:772:3225:6370 with SMTP id d2e1a72fcca58-776120794b1mr1953540b3a.2.1757671930614;
        Fri, 12 Sep 2025 03:12:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdOLWLt/kzZvoqv3qBd3aBrxag8UXrd6DQKl/PSVMJVtg==
Received: by 2002:a05:6a00:3a10:b0:772:6b0d:37ce with SMTP id
 d2e1a72fcca58-77605123021ls1666406b3a.1.-pod-prod-02-us; Fri, 12 Sep 2025
 03:12:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVeGtAEIf/FNkfkwKFnq75Y5q8H8NK/v2Lf7fjmub8w768sTCXAk9Knq10TKnyZYoq7wa7cGHyz3Nw=@googlegroups.com
X-Received: by 2002:a05:6a00:3d07:b0:771:fe9d:38f0 with SMTP id d2e1a72fcca58-77612091669mr3337512b3a.8.1757671928899;
        Fri, 12 Sep 2025 03:12:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757671928; cv=none;
        d=google.com; s=arc-20240605;
        b=RhjFv04OEv7W/UfGbjLilpkZnRReMB6ZYXmV/ZkCAQjfTyGOyBMFJZu0u78LYZ06pP
         vUfcB0eYZ6VNFXTOkFGlHaGLTk+5eikve23XMGRb11Xz10uYtW8SdWRN9PhYn+OA7Fx/
         1r7L3E0fIOFqCmHnfaEcqz3BAVvOsvIR/ibC43XzRmSt2sXqGBlch+aI+IYu66DslKxb
         f2fhuMMDtmCSdGIiwNX8m6BCuiyKihqH+BQpI6ZlVtSgiiigZZWOjxxGN/89zwCd8Dm5
         joPBOGuk2egRlzt5nChVLe4ooV8cvI2cC76Y/xcFn3whtqHLX44hGNM5PkPA9vfLsair
         699A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=E07gf3+EHiFZ+TUqDdqlrvhEU6rgl4o/YSp2RBqLkNw=;
        fh=U9JB1ZSHxcxw0vdkYjqkZsfFzs8JIs716xNZY6TdxdM=;
        b=Yjw0usGkI4G7AzZlMm2p3ab5sjqmElfhyZCo+szauRxIyGyiCR48YYvIZT1bUN+KSz
         +OEZbRaAtr89Y4+cRghIENm8UsN1L7c2/p1Yd61+XKWQA+cEK7ctxXBovuGbKiQIzb/r
         ab+5QHafG75pMrgQOAYSxPv/+fNjfslZX8ljTYlOgbX8IQszWlud+kxzZDPSfoPziD5y
         EDTPvAFTaqBJXyEWMOOiEYfWpMU68/ikCJwxrmnDU7KAgFVEzQJWvmcLNa69FqmddyPA
         ulEHHUs6U9dopEnl4BZPWl3DcgPLlfrxVtCjylWTSdmBUd4yMrF+pSdqlAtYrgqP2Jjh
         s+Sw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Bbw8DMj/";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52b.google.com (mail-pg1-x52b.google.com. [2607:f8b0:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-77607b487f2si173452b3a.5.2025.09.12.03.12.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:12:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) client-ip=2607:f8b0:4864:20::52b;
Received: by mail-pg1-x52b.google.com with SMTP id 41be03b00d2f7-b4cb3367d87so1131117a12.3
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:12:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVNj0nxVBgFpNr4rVs/dlT1F15XtbsJKrsu5v11tpwpZK9IuPQaGsAuxSrohp5BbcDNfw6/vAw0UEo=@googlegroups.com
X-Gm-Gg: ASbGncthoAZeaA9a+nu5KM1nsMY5/PAMNtuggvDk4ztDt/q7VR1tctwA7PF9Bdb7yOZ
	nGMhlgX9HWUYOqCoMUeyA+FBPFJ46rr56dztg3LR3b/BqqthxIMcqmio7EJmGSU/8JhrWehJQEu
	261RnNQ3VEfK09e72fkTqEUMgPk09dBxZ9ic8HKTjSqScbYno2oRRsfieN820bfyfTR8VDevJcz
	Nt9Uu+4Tg64FNBfjXLeBJdd61LnWojdDuiZhdfAR4cfLTJVe2m9eXWsMBv5pV98bDaPS7I5Jn8m
	/3zjaDHiarFkD8lyb8Mm12D9G3lvobcZXLurnqNEbFzjWeehIasb+0ZwPX2xRqk99mtzoQO3qa7
	RYHE22ogvyhvI8DfT0uQNmSqDPeuuEtcRIfOvRGo=
X-Received: by 2002:a17:903:32c4:b0:258:f033:3ff1 with SMTP id d9443c01a7336-25d242f314bmr32759845ad.12.1757671928125;
        Fri, 12 Sep 2025 03:12:08 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25c37293fd4sm44061135ad.38.2025.09.12.03.12.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:12:07 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Mel Gorman <mgorman@suse.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Kees Cook <kees@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Rong Xu <xur@google.com>,
	Naveen N Rao <naveen@kernel.org>,
	David Kaplan <david.kaplan@amd.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Jinjie Ruan <ruanjinjie@huawei.com>,
	Nam Cao <namcao@linutronix.de>,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"David S. Miller" <davem@davemloft.net>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	linux-trace-kernel@vger.kernel.org
Cc: Jinchao Wang <wangjinchao600@gmail.com>
Subject: [PATCH v4 02/21] x86/hw_breakpoint: Add arch_reinstall_hw_breakpoint
Date: Fri, 12 Sep 2025 18:11:12 +0800
Message-ID: <20250912101145.465708-3-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="Bbw8DMj/";       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
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

The new arch_reinstall_hw_breakpoint() function can be used in an
atomic context, unlike the more expensive free and re-allocation path.
This allows callers to efficiently re-establish an existing breakpoint.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 arch/x86/include/asm/hw_breakpoint.h | 2 ++
 arch/x86/kernel/hw_breakpoint.c      | 9 +++++++++
 2 files changed, 11 insertions(+)

diff --git a/arch/x86/include/asm/hw_breakpoint.h b/arch/x86/include/asm/hw_breakpoint.h
index aa6adac6c3a2..c22cc4e87fc5 100644
--- a/arch/x86/include/asm/hw_breakpoint.h
+++ b/arch/x86/include/asm/hw_breakpoint.h
@@ -21,6 +21,7 @@ struct arch_hw_breakpoint {
 
 enum bp_slot_action {
 	BP_SLOT_ACTION_INSTALL,
+	BP_SLOT_ACTION_REINSTALL,
 	BP_SLOT_ACTION_UNINSTALL,
 };
 
@@ -65,6 +66,7 @@ extern int hw_breakpoint_exceptions_notify(struct notifier_block *unused,
 
 
 int arch_install_hw_breakpoint(struct perf_event *bp);
+int arch_reinstall_hw_breakpoint(struct perf_event *bp);
 void arch_uninstall_hw_breakpoint(struct perf_event *bp);
 void hw_breakpoint_pmu_read(struct perf_event *bp);
 void hw_breakpoint_pmu_unthrottle(struct perf_event *bp);
diff --git a/arch/x86/kernel/hw_breakpoint.c b/arch/x86/kernel/hw_breakpoint.c
index 3658ace4bd8d..29c9369264d4 100644
--- a/arch/x86/kernel/hw_breakpoint.c
+++ b/arch/x86/kernel/hw_breakpoint.c
@@ -99,6 +99,10 @@ static int manage_bp_slot(struct perf_event *bp, enum bp_slot_action action)
 		old_bp = NULL;
 		new_bp = bp;
 		break;
+	case BP_SLOT_ACTION_REINSTALL:
+		old_bp = bp;
+		new_bp = bp;
+		break;
 	case BP_SLOT_ACTION_UNINSTALL:
 		old_bp = bp;
 		new_bp = NULL;
@@ -187,6 +191,11 @@ int arch_install_hw_breakpoint(struct perf_event *bp)
 	return arch_manage_bp(bp, BP_SLOT_ACTION_INSTALL);
 }
 
+int arch_reinstall_hw_breakpoint(struct perf_event *bp)
+{
+	return arch_manage_bp(bp, BP_SLOT_ACTION_REINSTALL);
+}
+
 void arch_uninstall_hw_breakpoint(struct perf_event *bp)
 {
 	arch_manage_bp(bp, BP_SLOT_ACTION_UNINSTALL);
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-3-wangjinchao600%40gmail.com.
