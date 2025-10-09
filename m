Return-Path: <kasan-dev+bncBD53XBUFWQDBBC5KT3DQMGQEAWOF34Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id A116FBC89E4
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:57:17 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-8776a952dd4sf28563116d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:57:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007436; cv=pass;
        d=google.com; s=arc-20240605;
        b=BWOMwezmobZE+QM07w4DKK5yQ8QfcI++TL3Db9i1kaC0RP5fF/mbPMXRBlZfxmTe5u
         VNYuUahZ37/B7Ej5mEM8msr2rupWpP+lh9Dz6aUJEcxt5c6VxAKbPYRjVeTfEmAGddaU
         2cpOmlNFoX6cdNvzfKZfil9ClKrL018rqukyhClV2+R15MWHsQwC5l8bYeyJh1M/aLDH
         QLN9yTtHLKtytCDR89YRQ+bJAj9J+XTPMLsPBb64Pw70w60fayWIBlAPPES9sYqRzQxC
         Ej/U+08CASoRb698jI+t8OMAkWiEJH/yw8yNCJNSIYoNsY4qdXpUxYC3A71NDwvA1IsY
         3Q2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=JlmQ4Xp7hWvT83K+bxoOGfaZsrS0vElwlKOy6z9M864=;
        fh=P52UNwK2lkoCH9o+KH75wpOxeODev9kU0jGEOJ5DHB4=;
        b=RD9ahtVUUgXRJvJU84hNLrY9JHUhqSpfqBxolxlA0qElrRebRVT5vwXiL4vR4gmqXt
         yji+Ud0K545KhS7ZWCNOJgO86ggUI1j51FVtiRGAICKf30972c7fMr0BTuSGvPvwJSGr
         Kg3/zby7jWnouh7XgYMF2VJR4MT/c+kURBN51vna7tvZk68rwPQF/zW8AYyNWJHros97
         vCnfi74GGNoD0aP9QASaePOJWPSq3CANRwb0svrUGR0x8JRnc0gk9gpgs77F+JoDh7FE
         gzr4+ILDS4PlOq1cO70JiQC5+gmjySVoQVDVI7Nh7UnRnt7YhGbQmDhyuPw0OwFDOzhr
         DXKA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nhfzyU3O;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007436; x=1760612236; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JlmQ4Xp7hWvT83K+bxoOGfaZsrS0vElwlKOy6z9M864=;
        b=O/wD78H5OLctV+uxxrki5hXWMsYxHhn+GMCXQidckSuCjRctskYsO5p5hq4uhRZnOv
         S4HrEfLxIhebsilSSQeMySGMFSAxA/YOqx2LT6uB+5AMBU/qzbOXUVl6qvhZkExRZH++
         3XYhyI4aCSvgvZRY88QI5hM9WKYNW8IxOvQMgxc9TMwDkrly4vtja4X2HFTRp1pF5001
         iM2nCWQfrj0VIiI1jimcLuroQ+jv/apSLdD1RjRCeOem9Z6mxrhb5icD4ZcZJvQjjUBz
         LgBc8QyoPXqCYUA76DqCjwE7HUHgQ9PxjT1B/XpOBzWOzZJKCeVhtIh9r4FuWUSDubSo
         J3TA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007436; x=1760612236; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=JlmQ4Xp7hWvT83K+bxoOGfaZsrS0vElwlKOy6z9M864=;
        b=OB9F2F8R8RbE4DJwyjSl4gSxlucddiiulq4LKHSSSuDPkY9JseaT+TeVtO8zcmPbAb
         asbEafUcDSl2y5FP42/wlKgwGCfOnQfpdooWByPRMpSR/h/S2hk0u6C1V/aD2JxjCH68
         NeMK912MO8GSmNCZwE6hxkPm7PcM85AYe5Yy/hEUKnIvOdj7d4P73i8VFrR5Pg/eftTM
         EPyAOGuinGIz/87EpI6znqcFTk3EVLESRorSB7ifz6P1UvnKcvje3TfjUnLuj16jIxPG
         4045RxY03BD2igJaZsfBN5GVavkCwNkgIw3IsiPsEKIuZ8CQII3nz50Hn94UOwdh4Oyr
         /mjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007436; x=1760612236;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JlmQ4Xp7hWvT83K+bxoOGfaZsrS0vElwlKOy6z9M864=;
        b=wYqAYkHSI/KkZeA0r7MzchOnccb2U1V8Vdkt5E0/1Ogj3HFbO1TznTwP8IXBclRpLA
         CyPjpopwU60Hu0rE7QWWWg00YVgbj7U+7j/l6Nso8YogdXFLH4D6oqVbPQnVZH9bV3mk
         1fiaa0STjL1eROpSgfUmn6Zun9F4vHnPTvNM7XChmDpnjf/ztZkcmtlrNWSQPJY/azeK
         2Kt9ta0oDEbKXx6p5yUW02xrTzRF+YnNHJb4uZci5f+OVtcu1FwE6F5lfTK1lZ/yRcrw
         BgmGHPr4kD12RT6rpCssNQNzehiAORdPNMnx0bF1A9f5+rrO5fvtknkP5VLfM38BtSrQ
         qhZA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVZpnkMAPxb4H2RQsl00GLkl06GvV2ZqoP0GNVYDVAhAKjXUcaaKDKCQKaBC+8LP5iILkTftg==@lfdr.de
X-Gm-Message-State: AOJu0Yx+RBy111M9Um43x+ZsLeyyvKSsLL3gUWlql4fdlersA7DP06AH
	yufdEiS2Jo793uXzdf6c7wY/didMAgaL2LgP8jXEoWiDZa6Jr7jfzsos
X-Google-Smtp-Source: AGHT+IFuzY7mcKyWhi+mzQG4WpnIRP+ZU6uMdb2xFqoc1UGA0v9WdceWCtJ/QveKMNyZyipMY9iC8g==
X-Received: by 2002:a05:6214:ca3:b0:7e3:cfe5:9972 with SMTP id 6a1803df08f44-87b2efe6f6amr106105896d6.45.1760007436175;
        Thu, 09 Oct 2025 03:57:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd49B9Ztevu/tLmwTSKaxiSTxja3NiOeLunC7ykf06p0rg=="
Received: by 2002:a05:6214:2f0b:b0:779:d180:7e3f with SMTP id
 6a1803df08f44-87bb5093867ls12371156d6.1.-pod-prod-01-us; Thu, 09 Oct 2025
 03:57:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX8n+x7oL6UBwp0yXquji5zXlJFyJZN705hUQxlyhSs/muHBo8a4O3ZGYOGpbj/zA7mLCZT8lSIg0k=@googlegroups.com
X-Received: by 2002:ad4:5945:0:b0:7f9:5850:70fa with SMTP id 6a1803df08f44-87b21057be2mr75870556d6.6.1760007435413;
        Thu, 09 Oct 2025 03:57:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007435; cv=none;
        d=google.com; s=arc-20240605;
        b=OVkWXn1nfAp+RfBJxm6zjj5KfNTMDjc3Woai0xQXt4uCXmj2B2qeFQ1isrdxizZIOG
         xo8YFNfHzFERpzKSo8Z/AWIxMvmwHQIU2mk42V5Wd13xamZtUlCrF+uvgJghuisTAvy0
         ICXSjE/XaPE6F7muK4d+xnuOcjdhsLyuHzjOUnteJN/89+orem4esTJ2+7iAHwpe9m+i
         1uHLHe1b0D7O0CjpT22xuiA318qhAZQW5kGyYXooD9FjH+iRpK57Go4PwKh4vLxzbwPk
         cWhLw/PtLx9MpmkZ0kaR0etqE5VlvdPpUarq1xbnLCPJrn/EoFl+jNrutjnXFN4c4qoq
         wCkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=bd/jIJYyk1G6SYf0mNQVLBMDX4oiGoErfqkyMXn4+LQ=;
        fh=Y/1XLCIlGyaU2XWkNovHA7Wibda5UsoCnMtWS1rdiyM=;
        b=UWalsv4DRsKNS9B3JxA7Kl0O3zK/fWWECFZuyJ4IOJWhz+EdEUasK1/QdyPIRMOA6v
         KZLhrKDkLeQLmx5AM3oq9o2+0bMqBIPZUYrGmpfqkpDH9y5ktMMb826jxaA18ifMO+LE
         VgTBEwvYGk0j4OlbOncv4ZpDEAoCC6olzm45xVmwpq7wifvCMciTBEl8c8oxybrHvAv4
         NBETRYdcO/H+nUZFbC9ehfz2w/H3ZhcBqFYWUGKceGQ0u39vHE3GecjGu5oZYWeHGxm/
         NjtmIUWSLyXilQcrcp/nkUMlUWa3vB45Y6X02GvO1p+mAFfpCtTK3gfiYRwRQ3vzZEkw
         kwpA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nhfzyU3O;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-87ab6bf9a54si198296d6.4.2025.10.09.03.57.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:57:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id 41be03b00d2f7-b49c1c130c9so496118a12.0
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:57:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXnS9G5iHUqPE3o5NN503NapyCSdlV99Hw5M7FlPPOCLNFPNuJ0DUUGUy/CYlRJw3D0I+c2dsRXk2I=@googlegroups.com
X-Gm-Gg: ASbGnctoBD5BP5DhUgxw86rs0ZSg6x3aA3bYu3fGQ+S4wKimZuckYfj9bNfxipoSDHi
	gRA8T0oahNwzixaUMKBIV5v/Y/vhpDaet05C0L78mEd4DAaqxO9ASQefe+LOYVnxpWgoxP5AwCQ
	E+7ORCrCHKwi+Er3uTnn8N+66Z7ibzgI/itjnssrA7elsp6juYTSPBDunhTSNMRTMlMi4ivbEa6
	Sybfzv9tUppSA5n3vdzqMKqUnR2NHj9OrBSmuZKeHtGClNLgmr/51JCnoURp3mNnxVKFSbapneC
	iB7kFIuIm05hME5oTFtacn/11ikTwJfctmlPa5XTQKKYXlCnwChx9npcQrPcA7XVcHAaJoxy/sp
	nReU6N46G4DrPWQTQETyD5CHfGEskheT3kCOUJqcs9s8qJAKJqK+hLzQxp1DQ
X-Received: by 2002:a17:903:2c06:b0:27e:dc53:d239 with SMTP id d9443c01a7336-290272b547bmr83465905ad.35.1760007434817;
        Thu, 09 Oct 2025 03:57:14 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29034de9febsm25266445ad.7.2025.10.09.03.57.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:57:14 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>,
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
Subject: [PATCH v7 02/23] x86/hw_breakpoint: Add arch_reinstall_hw_breakpoint
Date: Thu,  9 Oct 2025 18:55:38 +0800
Message-ID: <20251009105650.168917-3-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=nhfzyU3O;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
Reviewed-by: Masami Hiramatsu (Google) <mhiramat@kernel.org>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-3-wangjinchao600%40gmail.com.
