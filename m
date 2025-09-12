Return-Path: <kasan-dev+bncBD53XBUFWQDBB5HDR7DAMGQEBN7VC3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 343ECB548DC
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:12:06 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-406d2dab9b0sf25078055ab.3
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:12:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757671924; cv=pass;
        d=google.com; s=arc-20240605;
        b=BDKdoLGPx72d9a9D4yQX12hWiaWVVSK3AyMuJqWDNxDGQ4exWtpUdUWSlH6zKI6nRi
         +TUXmznNYaNtl5MYz9eqJfPi9GWJCxU59iKRcoGDJsNAXlho9PkVgog3Zn39QFPpX20G
         VG93b06HxgT6TfCed1iMsNzxUfKfzfwxqPOFTH4M0kTHYvcVfM2h+jYOCtJqghH+Yub/
         35QJ8mdh9E3akVH+OoCZZiQ/NHmFI0cSJtkajPGEvzvOP9nzSdTy4pSONWZPHcCxlMR5
         81JFMIv9s4p2/JaLzhbT0KB6qaj8N3H9BZ56rYkXTpIuNcJrVpqTukQjTrNIs+3yx2z3
         Z+RQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=7T+JRM4jNI9H85cFB8b6gEc+M/ju+q4Sr4QHZ5RT7Sc=;
        fh=0hTXixhuNwIYEhaPAgOjf0HtFFBSD8GU3Vfww4aVw14=;
        b=b/xXGrlXrqE4bFMUDfe92bdI2K78uu7OrFmbsoQlZ3o3mPJ1/DnYdq2xUq4E/Dvv06
         h3h0RNa0XGyqjFajjuW8SwSijDDfn/JbvHk6agqXV11XDXq+OiMz/FY2C88qDa3mI5BQ
         c81z43Ya4LEglmqkgxktX7qfyLStm1ZLdfINSUm8fF0Kg2/1lS3qMj3fk94pM+tGjPHk
         8y6u2R/DRbK9uo0xFNqTtfMMCn4SLcEACRzMSg5sXmZ6noHkNzyUqeCfnadhgHaplogi
         O6ElwSc+fQcrQ2WK9g1vF6kLauNrn77WY4Lfbx0cAK+rf/wqWlwEX6gzyeQmB33SJfuE
         5CFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=W9fYw+DN;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757671924; x=1758276724; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7T+JRM4jNI9H85cFB8b6gEc+M/ju+q4Sr4QHZ5RT7Sc=;
        b=w/XSDH1aMr9D7opBFLZH5nw/UB7cMSeV/q8x7NeqUPuG38qo2drW4PnovcAOHx//UE
         8+peTe9br05OrUcC6oVc4EI/NkwyYqm5DquhPUrDHSuVlz++h2w1RWxfVkZ9XjoNi+sx
         nfWUqxW5tXh4X4KApAcUt+ExkI2bOffLdxqG8gPHFNMQLymS9lJFDhLUAX6++UJGOzdl
         d1GAjHPKJihFPXSbwiQ6tpQ8t0rg7UK0Vj4cSomYAZQRZ/ldp2lhfEoxaDnwQxRKVBh+
         zhPWQLZYt6TrtgNvCCVOFhtmJQaDYx0mbw5R9QrOyEhy1HGBgk5Eio55UwR0NazCHEyF
         csIg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757671924; x=1758276724; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=7T+JRM4jNI9H85cFB8b6gEc+M/ju+q4Sr4QHZ5RT7Sc=;
        b=iaLYZ+YYGLW6ZFW3MtTENQHqy5HOIxTVNaecEj1G2GLDUWskAGyb9WESOKcc7LL8Pu
         GnpquJFBKwh/6ZG4SYretJ3vUQd3NCP9ER6uL+sF7e9RPchNc2CoPOQD9AWi1I8g+H3o
         2gOsqvcnXMyTEKew6IXgWH82t5OqKQdGqaGKzvVXhbn4DwXlOWx+GOsCif5PgHVtY4ac
         XoUPRySDkC0nkSHvX6kdBy1TPYI0htf0yX3msYVsg+Rff2tfWrZd/ya1uYz220wH3Id9
         OJBh+hYeKz8rfCne4cAZO2ZWHHYJbFdxk5IAyFPyvrkGl5Somvyy4rOtT6DDLyI3l3fa
         r7ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757671924; x=1758276724;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7T+JRM4jNI9H85cFB8b6gEc+M/ju+q4Sr4QHZ5RT7Sc=;
        b=TsKyTnck6X2/NvZMrmqpOR9QcvazcO+P4xhi1iMMwd0olWTd40Hxa+GIy/YiwftiLd
         GdC5hlIN/husX6NLwS6AgUa0La/fSThDLMp/uRSHpL3yWLO8rAvajf9RRZnd7Z1bGjek
         XxWSYnj9ys82x94g9M5QwQPSV36LIki+D3TTk6isky6nYZ2gngNoMKNvyGBMrBCmAPI4
         J5aObP3WMJr3zdPjY1OgTMzOWjHKISf+7F4ImNJ8Mfg018WpgDOBLnMTYiBPEu/wLRQt
         im3/ZKvlK5jJ4ZHz/DvWzws3cXLBsYYJf8Zbz0MsKKR/ghXwWgRipIka9ifmmxZf7tua
         F/Qw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWKix8D68u1TfGrqQcaOFPmC+Km+L3zhaKme8PePm4yFUItN0oIkwfA4N210wls1ZnXVoFvqw==@lfdr.de
X-Gm-Message-State: AOJu0Yyn0XLFyXwfVvBgN4dKKN+FAcA7Sbcq5BEDol4dFSXRrsB2PWcz
	ylLsalgoSyxZ5+E6zJ3nTq2sSq+AX5JTeCCe3V6AeXMis9E9f1vnleNo
X-Google-Smtp-Source: AGHT+IFHuL8rYOHjRglcgHMHqcOhLNMQC+xUbRV/rTDKmXj90bKZv37BjFQ6QQQYQRNkOygoCa1zqA==
X-Received: by 2002:a05:6e02:1c0b:b0:40e:1aee:2a55 with SMTP id e9e14a558f8ab-4209e83424emr36474295ab.10.1757671924554;
        Fri, 12 Sep 2025 03:12:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd/2rm/eFZRbvYKaL3UmbOaka//0ui7LdXpJG3aNFFBnQ==
Received: by 2002:a05:6e02:16ca:b0:419:b24f:32d with SMTP id
 e9e14a558f8ab-41cd681bbe9ls15740435ab.1.-pod-prod-03-us; Fri, 12 Sep 2025
 03:12:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWeEDs8byLICkC+1B5S6BZB8OSq9eZWim/eMBaVwqTQX5MZJtMFRsICpEiOupI+9dTzyQYEEEBktvk=@googlegroups.com
X-Received: by 2002:a05:6e02:168d:b0:3fd:96f6:375c with SMTP id e9e14a558f8ab-420a52b8780mr38004345ab.28.1757671923684;
        Fri, 12 Sep 2025 03:12:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757671923; cv=none;
        d=google.com; s=arc-20240605;
        b=CiXwF4ap6SLx9w7DYns5eQTzDoPHOxTa9O3KhICxZGaqQ/JEBvjt2jqcERr3yygcwQ
         4lrqbKQN5jsIoxJnvjg/4/DBQ8SmF+d+qL0y8vJ2Xx2wQYTvHsjBQuQwtMufNhnbOi/X
         idnD97wIg71fFROVsBd4r0vKqcnDMr9fU/Z/33hsthVyRWRBHdSyZkZ02SofFFKvl0sE
         CjQIcQRRRaKKOWFgKNkuA6d2dnqmxaqbJ7fB7TBbo1Cf+N7fAvy7c61xzyJld+dotHZ6
         hlOiG2dIlzFIFPERa//Yei9mnH2kLcacoJu9Betpo4d1d7LM8hF797DMvBD6RqvUqq3X
         +9pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MiJ4BKoAQXxhATSlWNuzoAaMk7tQVn4VoD83Z8R1fnY=;
        fh=Qr5UfA9PHoL1G50BpnVJCUGaxq32M9FSAjchBK9FRwU=;
        b=Ts86NGzY+4sSRdIJYT8KBKei2NgYQyIvBRZ9k58Hxe3yNFsHlnERileREGwSBDCf59
         y+2YvUgmZtJq2FUnK/x28Rbtd8nJqnuLx5oAX7jtWC9CkWr1Vn1EE08qedliSGjjWrRB
         8w0F1jiyL/Mw55arSCy0mso12s/CVg59DEsvTjey79xqGhmbBAyswRl/9hDYKb1bAGKp
         hXKT1p0Kz0aNe/Pxa97aWRbGa1JzNpUMncYCPmN0HTkExoPMb5XGCcZSTvcvCz7slmu5
         lfMqKODsmxsTPIr+jQq2mzHvaDMSFL+3zDg3blOjhPnscuyGXgNfRYNFSXLN/hjfRWp/
         AvSw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=W9fYw+DN;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-511f300906asi162116173.3.2025.09.12.03.12.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:12:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id 98e67ed59e1d1-32da88701c7so1818582a91.0
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:12:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW+/htXJw5yxhHE5emwcO/JU05HGGW48lhR/ctxT+9ulADW5SHOJT6Fjgb4F0/AjcxxJcAVIpTh9GQ=@googlegroups.com
X-Gm-Gg: ASbGncv6mDqRHWnZzJu6n0V1KbP4ioD0x5vBKMe2mbwBaUOrI9qWAfjSszjJoboZbWQ
	wewH8lOLRv/ZVh9LBYY4tkvdSOYxlNgo7+aNOt91zOngCV2MFjYf7K5lBsXoD3vkr9pwZOajrHG
	OOtkGTOesdeXXD6aJE4KJew7jZYkVMwi9j8tJEyo/JMzEwmaNNsJ/99k3RGKl37KFADd3glnfuv
	pk7oogBIPpyZ08LfeKdiI/f5Sjv59iS0CvCBmMDtdEbbe7hhA71Jwal/jjMPTY3XGgeuZVVj4ED
	/Z7UjKRh39CU1ezFiUO7s6SFg5Fhkpikbo7QE4dR8AbygHyEeKpYb21nwvWAUu/grEftwGTkXas
	y9jiuGOwvfzNsZ1WXrLAuvgEPOB+L4HRuKhAWbF7QcPrSKY4UgL7aBsKdcWne
X-Received: by 2002:a17:90a:da83:b0:32b:96fa:5f46 with SMTP id 98e67ed59e1d1-32de4e7488amr2457300a91.5.1757671922786;
        Fri, 12 Sep 2025 03:12:02 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-32df607d504sm76776a91.11.2025.09.12.03.12.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:12:02 -0700 (PDT)
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
Subject: [PATCH v4 01/21] x86/hw_breakpoint: Unify breakpoint install/uninstall
Date: Fri, 12 Sep 2025 18:11:11 +0800
Message-ID: <20250912101145.465708-2-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=W9fYw+DN;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Consolidate breakpoint management to reduce code duplication.
The diffstat was misleading, so the stripped code size is compared instead.
After refactoring, it is reduced from 11976 bytes to 11448 bytes on my
x86_64 system built with clang.

This also makes it easier to introduce arch_reinstall_hw_breakpoint().

In addition, including linux/types.h to fix a missing build dependency.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 arch/x86/include/asm/hw_breakpoint.h |   6 ++
 arch/x86/kernel/hw_breakpoint.c      | 141 +++++++++++++++------------
 2 files changed, 84 insertions(+), 63 deletions(-)

diff --git a/arch/x86/include/asm/hw_breakpoint.h b/arch/x86/include/asm/hw_breakpoint.h
index 0bc931cd0698..aa6adac6c3a2 100644
--- a/arch/x86/include/asm/hw_breakpoint.h
+++ b/arch/x86/include/asm/hw_breakpoint.h
@@ -5,6 +5,7 @@
 #include <uapi/asm/hw_breakpoint.h>
 
 #define	__ARCH_HW_BREAKPOINT_H
+#include <linux/types.h>
 
 /*
  * The name should probably be something dealt in
@@ -18,6 +19,11 @@ struct arch_hw_breakpoint {
 	u8		type;
 };
 
+enum bp_slot_action {
+	BP_SLOT_ACTION_INSTALL,
+	BP_SLOT_ACTION_UNINSTALL,
+};
+
 #include <linux/kdebug.h>
 #include <linux/percpu.h>
 #include <linux/list.h>
diff --git a/arch/x86/kernel/hw_breakpoint.c b/arch/x86/kernel/hw_breakpoint.c
index b01644c949b2..3658ace4bd8d 100644
--- a/arch/x86/kernel/hw_breakpoint.c
+++ b/arch/x86/kernel/hw_breakpoint.c
@@ -48,7 +48,6 @@ static DEFINE_PER_CPU(unsigned long, cpu_debugreg[HBP_NUM]);
  */
 static DEFINE_PER_CPU(struct perf_event *, bp_per_reg[HBP_NUM]);
 
-
 static inline unsigned long
 __encode_dr7(int drnum, unsigned int len, unsigned int type)
 {
@@ -85,96 +84,112 @@ int decode_dr7(unsigned long dr7, int bpnum, unsigned *len, unsigned *type)
 }
 
 /*
- * Install a perf counter breakpoint.
- *
- * We seek a free debug address register and use it for this
- * breakpoint. Eventually we enable it in the debug control register.
- *
- * Atomic: we hold the counter->ctx->lock and we only handle variables
- * and registers local to this cpu.
+ * We seek a slot and change it or keep it based on the action.
+ * Returns slot number on success, negative error on failure.
+ * Must be called with IRQs disabled.
  */
-int arch_install_hw_breakpoint(struct perf_event *bp)
+static int manage_bp_slot(struct perf_event *bp, enum bp_slot_action action)
 {
-	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
-	unsigned long *dr7;
-	int i;
-
-	lockdep_assert_irqs_disabled();
+	struct perf_event *old_bp;
+	struct perf_event *new_bp;
+	int slot;
+
+	switch (action) {
+	case BP_SLOT_ACTION_INSTALL:
+		old_bp = NULL;
+		new_bp = bp;
+		break;
+	case BP_SLOT_ACTION_UNINSTALL:
+		old_bp = bp;
+		new_bp = NULL;
+		break;
+	default:
+		return -EINVAL;
+	}
 
-	for (i = 0; i < HBP_NUM; i++) {
-		struct perf_event **slot = this_cpu_ptr(&bp_per_reg[i]);
+	for (slot = 0; slot < HBP_NUM; slot++) {
+		struct perf_event **curr = this_cpu_ptr(&bp_per_reg[slot]);
 
-		if (!*slot) {
-			*slot = bp;
-			break;
+		if (*curr == old_bp) {
+			*curr = new_bp;
+			return slot;
 		}
 	}
 
-	if (WARN_ONCE(i == HBP_NUM, "Can't find any breakpoint slot"))
-		return -EBUSY;
+	if (old_bp) {
+		WARN_ONCE(1, "Can't find matching breakpoint slot");
+		return -EINVAL;
+	}
+
+	WARN_ONCE(1, "No free breakpoint slots");
+	return -EBUSY;
+}
+
+static void setup_hwbp(struct arch_hw_breakpoint *info, int slot, bool enable)
+{
+	unsigned long dr7;
 
-	set_debugreg(info->address, i);
-	__this_cpu_write(cpu_debugreg[i], info->address);
+	set_debugreg(info->address, slot);
+	__this_cpu_write(cpu_debugreg[slot], info->address);
 
-	dr7 = this_cpu_ptr(&cpu_dr7);
-	*dr7 |= encode_dr7(i, info->len, info->type);
+	dr7 = this_cpu_read(cpu_dr7);
+	if (enable)
+		dr7 |= encode_dr7(slot, info->len, info->type);
+	else
+		dr7 &= ~__encode_dr7(slot, info->len, info->type);
 
 	/*
-	 * Ensure we first write cpu_dr7 before we set the DR7 register.
-	 * This ensures an NMI never see cpu_dr7 0 when DR7 is not.
+	 * Enabling:
+	 *   Ensure we first write cpu_dr7 before we set the DR7 register.
+	 *   This ensures an NMI never see cpu_dr7 0 when DR7 is not.
 	 */
+	if (enable)
+		this_cpu_write(cpu_dr7, dr7);
+
 	barrier();
 
-	set_debugreg(*dr7, 7);
+	set_debugreg(dr7, 7);
+
 	if (info->mask)
-		amd_set_dr_addr_mask(info->mask, i);
+		amd_set_dr_addr_mask(enable ? info->mask : 0, slot);
 
-	return 0;
+	/*
+	 * Disabling:
+	 *   Ensure the write to cpu_dr7 is after we've set the DR7 register.
+	 *   This ensures an NMI never see cpu_dr7 0 when DR7 is not.
+	 */
+	if (!enable)
+		this_cpu_write(cpu_dr7, dr7);
 }
 
 /*
- * Uninstall the breakpoint contained in the given counter.
- *
- * First we search the debug address register it uses and then we disable
- * it.
- *
- * Atomic: we hold the counter->ctx->lock and we only handle variables
- * and registers local to this cpu.
+ * find suitable breakpoint slot and set it up based on the action
  */
-void arch_uninstall_hw_breakpoint(struct perf_event *bp)
+static int arch_manage_bp(struct perf_event *bp, enum bp_slot_action action)
 {
-	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
-	unsigned long dr7;
-	int i;
+	struct arch_hw_breakpoint *info;
+	int slot;
 
 	lockdep_assert_irqs_disabled();
 
-	for (i = 0; i < HBP_NUM; i++) {
-		struct perf_event **slot = this_cpu_ptr(&bp_per_reg[i]);
-
-		if (*slot == bp) {
-			*slot = NULL;
-			break;
-		}
-	}
-
-	if (WARN_ONCE(i == HBP_NUM, "Can't find any breakpoint slot"))
-		return;
+	slot = manage_bp_slot(bp, action);
+	if (slot < 0)
+		return slot;
 
-	dr7 = this_cpu_read(cpu_dr7);
-	dr7 &= ~__encode_dr7(i, info->len, info->type);
+	info = counter_arch_bp(bp);
+	setup_hwbp(info, slot, action != BP_SLOT_ACTION_UNINSTALL);
 
-	set_debugreg(dr7, 7);
-	if (info->mask)
-		amd_set_dr_addr_mask(0, i);
+	return 0;
+}
 
-	/*
-	 * Ensure the write to cpu_dr7 is after we've set the DR7 register.
-	 * This ensures an NMI never see cpu_dr7 0 when DR7 is not.
-	 */
-	barrier();
+int arch_install_hw_breakpoint(struct perf_event *bp)
+{
+	return arch_manage_bp(bp, BP_SLOT_ACTION_INSTALL);
+}
 
-	this_cpu_write(cpu_dr7, dr7);
+void arch_uninstall_hw_breakpoint(struct perf_event *bp)
+{
+	arch_manage_bp(bp, BP_SLOT_ACTION_UNINSTALL);
 }
 
 static int arch_bp_generic_len(int x86_len)
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-2-wangjinchao600%40gmail.com.
