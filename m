Return-Path: <kasan-dev+bncBD53XBUFWQDBBJ5JZDEAMGQETWVA2DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 39942C47FA7
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:36:57 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-8803f43073bsf107760296d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:36:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792616; cv=pass;
        d=google.com; s=arc-20240605;
        b=PW1DVrC23xBni6vopGFJjfsO4Dl8GCft81+94E6Qg95SxvBjYRLCOnI2lf/U8QeSkA
         +CtwkcHBuYaqGmgw7JtbxnI7yYSoG01b/wBXJwgk0o4mo3Y+H0hLzbpZcwY+xCV0/NZh
         DQl3QrXxQdFegfbUgk4UjiPgzD98nSzjRYwwlGb6PjSGR66a6O+/haqiqhPtSJu68RfC
         jEia+vd8E0m1HHvTK320xJWmlya6WMWQlw2idCAbRvdEnIOXTr7PwtlfWWWxcbjkCPY3
         yLMjV3BEZSZQwPjPF04nMNZhVtaDg4Fmn3eMO7q5VAA/PD4Lc8O9k3QN0flauUq0Q5Eb
         zeMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=4sO/9OyByHuLxoYs2i10nZqMRx1RtZ2chk/EnG5MRKA=;
        fh=chNSm+RKN1Yd6WLAhxlcmq4931elsqAIo66d8mI8nBM=;
        b=bojCEpwSDWPZzMyMDoMDm+rDkPzJITvEF1Kiwdd2axRGPlsgiofUJvQGYjDeUVOPLL
         5fT6e4/I5xO2ZCbKFXhMiTnNmatlgYe1yNlyXCisiAyfOfynnjHBUknGsJuErdA8wEEu
         svnf0n6YhSnsWEVWWfmFtuLqSyzrcKVUl+ea/RlPjoWb3vTMm3gJsN4Qf82l8A98qMaq
         ER49zFPoFTOMaktxx8Lik0Fz8ZRjTLtF9muM4BWZUntJWLBBWFVhB6Q4JNGAuGmoiHxq
         GOmdneLIH3D0FAxsOWoUUFncAmHFFE2LMGWd9dp8fsRKhhD6dbx+0cele4TlA1l1sgpb
         rkiA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SGEj7Pp8;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792616; x=1763397416; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4sO/9OyByHuLxoYs2i10nZqMRx1RtZ2chk/EnG5MRKA=;
        b=q8Clb/iJ8VLn2pbQkoNkYgn05yXrdD8LF4SD4nTM2AQtoO6wxaRTKpy1kPJDrpxX+p
         rTR85FHKEhLuBfegaaOhES0pU5GtfP3tF2ZRN6CzEKsIMtpCDfFVLSmxmpRtE1VzSbCf
         B1BOonABSDkw4UDkkdOseycOJ2+2Fdc+wVDUqO8qw03a/kSlgPEm9l7iYsPdU0yCCTve
         I2Y6yTK7ruBvS3YnCZFI26LXV0RSFV0WyJqv61MaIIiSTUd4evX31WjtOVXDCBwgo5Cx
         LyZti1z0xZrD2sVHxpiLpBVcFFVQyuIfwtg2J2Tf3FDcKYq0tOXWuXbPLODAhuvuW/KL
         SHeQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792616; x=1763397416; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=4sO/9OyByHuLxoYs2i10nZqMRx1RtZ2chk/EnG5MRKA=;
        b=cX9CC6LsArELISYyuJJvV6u7pgTV1yLBjXQzH74PJFZOtcpyQ2QtjjyrvgkYz9HoOb
         FEcv3TXWMR3494aU2gUU9k2VkmGwDKdlodn7tF4ze1tN+1OvjeKqp9MzYOJ0oXOVVCAw
         v/IjOiaEeIBwqO9ORenwmsa1YbUEQlcEsh86Ait+ETuX9l31ekTMG6yBXabg0PGNDRbd
         H46oBKD6Zr+qxoMN3gHLW6PF01w+IM5IJDGd5wOOnjPvvfnXEeWQLzk0ws7ATSU/7t9W
         lY99GAew0K2piySrC4mVk3hDI0eYCbt8ZAEQgapbvLcUsK+VJ9kSnGHhju6G5hvswx9N
         QVlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792616; x=1763397416;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4sO/9OyByHuLxoYs2i10nZqMRx1RtZ2chk/EnG5MRKA=;
        b=vTlrvYxc/93Svb0ddDRlKtD1CSOje/1cVxPSJtZ5jfqDVitqi6Bn53HResEeujHH1n
         f/gPH5u6IIe6aE0AUctZ077h6Ci42YVJDAyCMTfnPpt6BMJP5ay8dIOrH5frrUXEvZMR
         2I28cJbBk1Tk5CTMp4BLMDbC8pbaV9rrOJwZJiJz58mnvu4yhrSY79WAbjk6+eM8/Ns4
         bkOZ5VRrXd9XecP9JnVxX0sdhEXJCoTMTo7cKdtBXLOUW9aq2wATqCZlYu+iTkLlBpL0
         JtzczbbtAWXS0UCntWGBZe7rIIokdQWOznWHu1DY5omDluBxo/TkOZBV0pc3TtMbUsup
         TbHQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVSA8dqzGbTOMB+jdvapkUROTx06oCWiz1wK3gigNqwdCz2y3bITbY7nl9B5/Z13KdQvCVCxQ==@lfdr.de
X-Gm-Message-State: AOJu0YzVXwOYOLgihnp0xW3CKS0huKLAabLXGQi9JoNUHXdCttbCFah3
	h7BkYdoHkoVhaz33NdSW8Xz+jKsFraxAx6BTWAfDWgRzzknrs2wpd0/K
X-Google-Smtp-Source: AGHT+IHQeYk5lCQ24RRHJNnix14HEhogi4W9i54AbS6AQ0I2Efg2xnRG41jJ9J7ddfLv83eXgOEF4w==
X-Received: by 2002:a05:6214:3010:b0:87f:fb2e:9991 with SMTP id 6a1803df08f44-882385cfb7dmr150382636d6.6.1762792615778;
        Mon, 10 Nov 2025 08:36:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+b8DT+blW+mGoqn9LKN8H5t5FQQXL3li3Kp3np+DVfPtQ=="
Received: by 2002:a05:6214:5e12:b0:882:4764:faad with SMTP id
 6a1803df08f44-8824765019fls24626736d6.0.-pod-prod-06-us; Mon, 10 Nov 2025
 08:36:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUY8x2NFEZtahl18bTfaEzw7mt9PjyzgqjvM7/AL5sNj2Ii4meoscSRqNU3ziz0hwAcrKOqye2gw3I=@googlegroups.com
X-Received: by 2002:a05:6214:765:b0:882:4555:f164 with SMTP id 6a1803df08f44-8824555ff95mr108971966d6.40.1762792614773;
        Mon, 10 Nov 2025 08:36:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792614; cv=none;
        d=google.com; s=arc-20240605;
        b=b+DBbTZZDWPvEzXMiqmpVCQs+Ol+JJg0cHYShdSMFnXoBJBhWtsd6u/AWD7sdCgyw7
         kslKAllZAg260FBXNR4xkZR7Cb3ZD0TgVbfyDKpzOrf0CzHE6oclZwHIdTycr/YWji6J
         sKnYrIA5uaya8IzVr8eTz0MoMHzCDFj+PfOfS67HrIm5JbS+l+GvnloFIJD7JJpEG4Oe
         5QTtovddOjntSXfSYSzYoJ8Tpg0p3Adi0MxckAoE/983J36YX+hiDGafGYrEgEzuRCdS
         qVqy7jhr4zlST5xBVvcyTLdRojtZrdroxkCkEMaUcSj1R0zz8qYDkDJaNMSFlDN/kmV9
         n6AA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=Rf1O2IW8PmKXDZ3O4r/3b4myYk+kPZmKXtIohIyK/BM=;
        fh=tBqvr2mXIVWwnBM5dWpV7z29xELVwDZa7YhUeNfaXnU=;
        b=BjUX5jjgaZIJKNYmwMOcWGBvn4BHIi+P0QkEETChBpKQ6ntFytUMfll2jI2riTPSG5
         oRuDxcm9evA78YHgcAuOyeaBKMdjhSNoqg/gx+2fRrU8Kf5riJ3D87p+FkDJVacsgY9N
         KL/QnrlyV7d7t1eJJAJCfjJWyKUcUMmKZ8+IqAgpMqnrvd/L2PswWeaYxFFxNSxkxtrS
         2Tq0gqpYCp69B/MLY/XqD+wfjaqGa544hFomzOWOhwfHJWj0i6cR5ACqLcjvRC/ZjFIK
         8abvwMUnSxUaUGU9GMbUXXWOP6v3wAP1sATtXcOkyF5WAMLQzIDyi4K7Us777OPs4PTK
         hL3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SGEj7Pp8;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102d.google.com (mail-pj1-x102d.google.com. [2607:f8b0:4864:20::102d])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-88238a16a32si5282806d6.4.2025.11.10.08.36.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:36:54 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) client-ip=2607:f8b0:4864:20::102d;
Received: by mail-pj1-x102d.google.com with SMTP id 98e67ed59e1d1-3436d6bdce8so2601335a91.3
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:36:54 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV/nKKNH7d8kBtn1iD1c66wtmzPni+AzMy0roMlqakcTc33SLGwkFduIHcDgBccM8/Cs9mCWrF7U+A=@googlegroups.com
X-Gm-Gg: ASbGncvCeBOWC4WvhZZtghwzWgSeKKeWNgAnPfZQuFbPL8kRrLiLFekDwapoBxChagi
	tPUR8sC0YGbVgHIRlHAKp40YygfiStdDXzGp8XeEZe1qpUxrYE31ZYXLoFepmzmTAGalsSfMHM1
	2woj27c4IHV2OuWRzLVtbh7PO7gI2vcDH4WZYY2GTyTQ17zukTRjy2g90dcIKP6qkkwYgR9TvhX
	3W2peXd984TjKKe7MWJFz70KLPGfkhLGhYMm1VJPji7mxFrWoOzN15bq1AaG8RjKrFte6gq+Aj3
	8krAe0Xn4JShUtXx90pSAh9YGH7KW0cwAbOFr6g9PtK1gI2c8eaMBfZ+K0E6iuDGVcYn/WBhZXP
	07t4tzPcvb5vwfgM3Djzb4jyiZUPFmdtdJ9XEWMgeb26qN1WIMkObcahUINakeTeJCNBt4tozMz
	KuvNwEaRHqOGI=
X-Received: by 2002:a17:90a:bf06:b0:343:a631:28b1 with SMTP id 98e67ed59e1d1-343a6312b7emr3517293a91.16.1762792613858;
        Mon, 10 Nov 2025 08:36:53 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-341d0adc41dsm5956374a91.1.2025.11.10.08.36.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:36:53 -0800 (PST)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	"Masami Hiramatsu (Google)" <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Alice Ryhl <aliceryhl@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Ben Segall <bsegall@google.com>,
	Bill Wendling <morbo@google.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	David Kaplan <david.kaplan@amd.com>,
	"David S. Miller" <davem@davemloft.net>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Ian Rogers <irogers@google.com>,
	Ingo Molnar <mingo@redhat.com>,
	James Clark <james.clark@linaro.org>,
	Jinchao Wang <wangjinchao600@gmail.com>,
	Jinjie Ruan <ruanjinjie@huawei.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Juri Lelli <juri.lelli@redhat.com>,
	Justin Stitt <justinstitt@google.com>,
	kasan-dev@googlegroups.com,
	Kees Cook <kees@kernel.org>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	"Liang Kan" <kan.liang@linux.intel.com>,
	Linus Walleij <linus.walleij@linaro.org>,
	linux-arm-kernel@lists.infradead.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linux-perf-users@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org,
	llvm@lists.linux.dev,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Mel Gorman <mgorman@suse.de>,
	Michal Hocko <mhocko@suse.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nam Cao <namcao@linutronix.de>,
	Namhyung Kim <namhyung@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Naveen N Rao <naveen@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Rong Xu <xur@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	=?UTF-8?q?Thomas=20Wei=C3=9Fschuh?= <thomas.weissschuh@linutronix.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Will Deacon <will@kernel.org>,
	workflows@vger.kernel.org,
	x86@kernel.org
Subject: [PATCH v8 03/27] HWBP: Add modify_wide_hw_breakpoint_local() API
Date: Tue, 11 Nov 2025 00:35:58 +0800
Message-ID: <20251110163634.3686676-4-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=SGEj7Pp8;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

From: "Masami Hiramatsu (Google)" <mhiramat@kernel.org>

Add modify_wide_hw_breakpoint_local() arch-wide interface which allows
hwbp users to update watch address on-line. This is available if the
arch supports CONFIG_HAVE_REINSTALL_HW_BREAKPOINT.
Note that this allows to change the type only for compatible types,
because it does not release and reserve the hwbp slot based on type.
For instance, you can not change HW_BREAKPOINT_W to HW_BREAKPOINT_X.

Signed-off-by: Masami Hiramatsu (Google) <mhiramat@kernel.org>
---
 arch/Kconfig                  | 10 ++++++++++
 arch/x86/Kconfig              |  1 +
 include/linux/hw_breakpoint.h |  6 ++++++
 kernel/events/hw_breakpoint.c | 37 +++++++++++++++++++++++++++++++++++
 4 files changed, 54 insertions(+)

diff --git a/arch/Kconfig b/arch/Kconfig
index 61130b88964b..c45fe5366125 100644
--- a/arch/Kconfig
+++ b/arch/Kconfig
@@ -456,6 +456,16 @@ config HAVE_MIXED_BREAKPOINTS_REGS
 	  Select this option if your arch implements breakpoints under the
 	  latter fashion.
 
+config HAVE_REINSTALL_HW_BREAKPOINT
+	bool
+	depends on HAVE_HW_BREAKPOINT
+	help
+	  Depending on the arch implementation of hardware breakpoints,
+	  some of them are able to update the breakpoint configuration
+	  without release and reserve the hardware breakpoint register.
+	  What configuration is able to update depends on hardware and
+	  software implementation.
+
 config HAVE_USER_RETURN_NOTIFIER
 	bool
 
diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index fa3b616af03a..4d2ef8a45681 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -245,6 +245,7 @@ config X86
 	select HAVE_FUNCTION_TRACER
 	select HAVE_GCC_PLUGINS
 	select HAVE_HW_BREAKPOINT
+	select HAVE_REINSTALL_HW_BREAKPOINT
 	select HAVE_IOREMAP_PROT
 	select HAVE_IRQ_EXIT_ON_IRQ_STACK	if X86_64
 	select HAVE_IRQ_TIME_ACCOUNTING
diff --git a/include/linux/hw_breakpoint.h b/include/linux/hw_breakpoint.h
index db199d653dd1..ea373f2587f8 100644
--- a/include/linux/hw_breakpoint.h
+++ b/include/linux/hw_breakpoint.h
@@ -81,6 +81,9 @@ register_wide_hw_breakpoint(struct perf_event_attr *attr,
 			    perf_overflow_handler_t triggered,
 			    void *context);
 
+extern int modify_wide_hw_breakpoint_local(struct perf_event *bp,
+					   struct perf_event_attr *attr);
+
 extern int register_perf_hw_breakpoint(struct perf_event *bp);
 extern void unregister_hw_breakpoint(struct perf_event *bp);
 extern void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events);
@@ -124,6 +127,9 @@ register_wide_hw_breakpoint(struct perf_event_attr *attr,
 			    perf_overflow_handler_t triggered,
 			    void *context)		{ return NULL; }
 static inline int
+modify_wide_hw_breakpoint_local(struct perf_event *bp,
+				struct perf_event_attr *attr) { return -ENOSYS; }
+static inline int
 register_perf_hw_breakpoint(struct perf_event *bp)	{ return -ENOSYS; }
 static inline void unregister_hw_breakpoint(struct perf_event *bp)	{ }
 static inline void
diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 8ec2cb688903..5ee1522a99c9 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -887,6 +887,43 @@ void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events)
 }
 EXPORT_SYMBOL_GPL(unregister_wide_hw_breakpoint);
 
+/**
+ * modify_wide_hw_breakpoint_local - update breakpoint config for local CPU
+ * @bp: the hwbp perf event for this CPU
+ * @attr: the new attribute for @bp
+ *
+ * This does not release and reserve the slot of a HWBP; it just reuses the
+ * current slot on local CPU. So the users must update the other CPUs by
+ * themselves.
+ * Also, since this does not release/reserve the slot, this can not change the
+ * type to incompatible type of the HWBP.
+ * Return err if attr is invalid or the CPU fails to update debug register
+ * for new @attr.
+ */
+#ifdef CONFIG_HAVE_REINSTALL_HW_BREAKPOINT
+int modify_wide_hw_breakpoint_local(struct perf_event *bp,
+				    struct perf_event_attr *attr)
+{
+	int ret;
+
+	if (find_slot_idx(bp->attr.bp_type) != find_slot_idx(attr->bp_type))
+		return -EINVAL;
+
+	ret = hw_breakpoint_arch_parse(bp, attr, counter_arch_bp(bp));
+	if (ret)
+		return ret;
+
+	return arch_reinstall_hw_breakpoint(bp);
+}
+#else
+int modify_wide_hw_breakpoint_local(struct perf_event *bp,
+				    struct perf_event_attr *attr)
+{
+	return -EOPNOTSUPP;
+}
+#endif
+EXPORT_SYMBOL_GPL(modify_wide_hw_breakpoint_local);
+
 /**
  * hw_breakpoint_is_used - check if breakpoints are currently used
  *
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-4-wangjinchao600%40gmail.com.
