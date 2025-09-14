Return-Path: <kasan-dev+bncBDC4FFVJQ4BRBUMRTPDAMGQEYKSLE2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id EB2EFB56979
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Sep 2025 15:53:24 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-32e00c72c0bsf1114412a91.2
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Sep 2025 06:53:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757858003; cv=pass;
        d=google.com; s=arc-20240605;
        b=gh4JcDLo3c1ou/4D6kSFPixRnlTAzt8MOyqixDNJT6OKe+BnBNnAZAv8ssEKp/NNOv
         gx7HNFb+Y99T9b3PsvZm3hLnVXqF6JeK+bft+fzyTAkCmLBzEMzAn/q24EXZOcgSBRbl
         mSJ3eXiA++q7APrGV1/9MXyc9RkcwY6sQ8mRA+6bi4BC20WfJ953JW9y/YFJbn/gyVal
         i4tPkHRObNVCkLzH+TpQVEBLHqON/LSIjON3wX27TRcv+TYaj+PxeBqOdcq2/3brRUMu
         D6j3gBQz8/NIQaIMzMqceIkPwghL4Y5HoGVO52t+kSs51gKK22XJOxAyXGmagoPhAguw
         4AIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=G/zuHuw76pqsSH59dFmS/svGoSGbUH7q09VR/v5pmyA=;
        fh=J/p6MItIFbKMRQL8Lem7ZmQvQdxHduqJEfCF6kbFoFQ=;
        b=QT9oZkN4Kda1yetnE9h2tKov6/UNgy0br1MB12fQMXk3vIRGyJ29IlljcklLMElaMY
         +PrjzbeXSoFYFZZN/v6UG7TSdZD4hDdPpm+HXHSj7aovFk72rm0ZIg8ZPOytQAc5YrRC
         ynhT8uTEChSqaGC+WlhWdoBjs4GYA5h8jU3+xRgmPJ9PPHaoX4r3+yIkZcl9MKRAoddw
         d6388hyQDO/jO9z9Dmxf9tznRQRJk3rvf0Nqlb7PChj0Xa2JACMhJn4PbwnyLd4aCRFF
         NsBXjBmehwxv5uXcHELkl2kjPaT97hjcvAjIt3vu1QAajG+f+dNjiQNeD49+y+nEh2zW
         JUpw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Hm3bsaZn;
       spf=pass (google.com: domain of mhiramat@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=mhiramat@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757858003; x=1758462803; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=G/zuHuw76pqsSH59dFmS/svGoSGbUH7q09VR/v5pmyA=;
        b=Lt+VBiCoPUIKIobX9CIWncX/GSMTNhY558X84MDWGJrRQodDLdcKQqkBB5CTwJPIhv
         FemYiMY/R40+O1GX96xswYxzuJzm1H6tf+LuMubWylFW/crO9K14moVOO3vwD2+gOfI3
         k1aaUL0YQcnaYPMJ50ADV5BykZNtcQFwny1IHBMt0x8E/x6YCl8/SfF1H8E+NoobOqsO
         0HJHyOd1F73FZmmclPWOhq4+SUra47ApEG+a7TQ4QF/8cIIjlGwErq6b1UmZPCwB7C8Y
         xntboVsmduOXrIqdkW2E9Juc3Hk0jvRa2qR/0MkCWH/K0NqFBJbbLe/COEouLN9oI4j+
         eXfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757858003; x=1758462803;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=G/zuHuw76pqsSH59dFmS/svGoSGbUH7q09VR/v5pmyA=;
        b=eRYK3jbzhqTOqHzbbk8SwvYV4SXkV3iE0v6rNdAkCxHiztzPa6nL+xtBefltfpffhP
         jX0yYRiytl37bDghPqy+90xvRpspmQW/xil8RH83MQTgMahniTtBj8hVOFpHrN37H2f8
         7p3fIOh4xy6XA92YmgCe68yrPbxbsL7Lm2UlJvToKKzA2BqBsHWNU9sQtWx7zdB4oGW5
         UpSkjsBO21p1w3IRadNKpq44i05Kmja15vgvOToQIipd5msa7Edefi6sBloBwh9it3i3
         UAUQR+EAOJOKOeyz4n+A1m/SRiOv/mo3vwOgEFWpBc3+BmU38hZ8m4eMmhYaw5rqQHLJ
         ibjg==
X-Forwarded-Encrypted: i=2; AJvYcCXyKJMkvrpd2RElQCXyY70ZGxaW1jkYfsqBpYu5zs5iqAyewDPRqxooxLkiHemkqDnGR6IwpA==@lfdr.de
X-Gm-Message-State: AOJu0Yx4aGqcTa/EwEvpVDJdn9w/em3RwwzhZwqE7FTe/ZnWkXN+PfoT
	03EjR9MgwDlf+4mV+oOX8hG0clvicctVVoSuMeenGSre8fUwLf0gCHw7
X-Google-Smtp-Source: AGHT+IERH0TaSE3PD7YCFpVaCWbYvaC6xpprrsHGKEkJRVwijmA7qeorvOrt9BnK5oogsKiw3x8Tqg==
X-Received: by 2002:a17:90b:1a84:b0:32d:a670:bd42 with SMTP id 98e67ed59e1d1-32de4f8569bmr8529591a91.22.1757858002811;
        Sun, 14 Sep 2025 06:53:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5GDBfLvnc2YIRO6XBFWtHqmGbTqqO1OPqJmJ9cSvIPqA==
Received: by 2002:a17:90a:51a6:b0:32e:1c82:1ee9 with SMTP id
 98e67ed59e1d1-32e1c822133ls629667a91.1.-pod-prod-09-us; Sun, 14 Sep 2025
 06:53:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV6OLROJ/5zMTjUl3lfJswFbqET5luDWOCU4mjD606Cwa2If7aZxUyuI1YL/zL+wgeVHfRY+DGLitE=@googlegroups.com
X-Received: by 2002:a05:6a20:2448:b0:262:82a6:d94a with SMTP id adf61e73a8af0-26282a6e026mr4866756637.30.1757858000469;
        Sun, 14 Sep 2025 06:53:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757858000; cv=none;
        d=google.com; s=arc-20240605;
        b=c/z6hVm4hawtfJto6lGwoIgoedmZCMwCbw99fujcYWL6ORYaDRBSQkZb8g+hR2yr0V
         An0kDWNBD3zSZBFMwuReSIAuzZuvo6K3D60FQIZ6FP9PaPRa6MHXML39WirXe/GzDgqA
         rGbF1KFqu9BQAvIjg+QfOlzoBvQpM918NxtcupXJHw7fmMcnR80WZrGEfUPq2KtRHuUt
         f1xxETPYrypSfI5L9epfQQN4GJW/aOn05tBDU5hpuIJAks+jFRS/mnpa3K2epYLChkiq
         8bWx+l2jr7mmBMdga+iMLYQ8pBrQRYpUnVoR5/I+Vyn081FLH6EGloqff+ziJCoEBL+N
         c/dA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=UT3BD6f28q3caqcvv9tNqfI2EwehMhyKTfYqk9PWNbc=;
        fh=NQeqbZfMKjMy8NaCHM8JPlpyfQbM5NGco4RXkoRnpTY=;
        b=EBLstJR30/DYci51TU7wfk6xKLjr6iPbCa7IlYB6wdx706+jCHm5vRj6W5Hr88LbV0
         DDGljU5lZK7iEAA1hQRNnNBsoFducOUhL5FaminfaHZ8WfvzNnCrA5IGK0PumBdUq1Ai
         acYfLPD0i6qWFKD/tfPg3KqoSTyjwcSmYWHTvPZ1QciI0tHKph78Mkm+U9m7/w1asTP4
         VyfHpZvQF3Y4vXwrLKYb8XU9KDQ1V7kRuoM1Tv0+KXMtfkFzqL37rj281T2YLXqA/cfC
         ShlNO6R4mFwNA3gbBbCDyaR4Fj7T/5bYCPWle1SeZRBLMFOE9pgzUE9oLfvsNK5HCiyc
         FA/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Hm3bsaZn;
       spf=pass (google.com: domain of mhiramat@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=mhiramat@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32dd61f6fffsi336195a91.1.2025.09.14.06.53.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 14 Sep 2025 06:53:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhiramat@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 43C26404B0;
	Sun, 14 Sep 2025 13:53:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 95F0FC4CEF0;
	Sun, 14 Sep 2025 13:53:08 +0000 (UTC)
Date: Sun, 14 Sep 2025 22:53:06 +0900
From: "'Masami Hiramatsu' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jinchao Wang <wangjinchao600@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Peter Zijlstra
 <peterz@infradead.org>, Mike Rapoport <rppt@kernel.org>, Alexander
 Potapenko <glider@google.com>, Jonathan Corbet <corbet@lwn.net>, Thomas
 Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav
 Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
 x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Juri Lelli
 <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>,
 Dietmar Eggemann <dietmar.eggemann@arm.com>, Steven Rostedt
 <rostedt@goodmis.org>, Ben Segall <bsegall@google.com>, Mel Gorman
 <mgorman@suse.de>, Valentin Schneider <vschneid@redhat.com>, Arnaldo
 Carvalho de Melo <acme@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
 Mark Rutland <mark.rutland@arm.com>, Alexander Shishkin
 <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@kernel.org>, Ian
 Rogers <irogers@google.com>, Adrian Hunter <adrian.hunter@intel.com>,
 "Liang, Kan" <kan.liang@linux.intel.com>, David Hildenbrand
 <david@redhat.com>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka
 <vbabka@suse.cz>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko
 <mhocko@suse.com>, Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers
 <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, Justin
 Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, Alice Ryhl
 <aliceryhl@google.com>, Sami Tolvanen <samitolvanen@google.com>, Miguel
 Ojeda <ojeda@kernel.org>, Masahiro Yamada <masahiroy@kernel.org>, Rong Xu
 <xur@google.com>, Naveen N Rao <naveen@kernel.org>, David Kaplan
 <david.kaplan@amd.com>, Andrii Nakryiko <andrii@kernel.org>, Jinjie Ruan
 <ruanjinjie@huawei.com>, Nam Cao <namcao@linutronix.de>,
 workflows@vger.kernel.org, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org,
 linux-mm@kvack.org, llvm@lists.linux.dev, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 kasan-dev@googlegroups.com, "David S. Miller" <davem@davemloft.net>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 linux-trace-kernel@vger.kernel.org
Subject: Re: [PATCH v4 02/21] x86/hw_breakpoint: Add
 arch_reinstall_hw_breakpoint
Message-Id: <20250914225306.2185b79065e32f60a40ef54c@kernel.org>
In-Reply-To: <20250912101145.465708-3-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
	<20250912101145.465708-3-wangjinchao600@gmail.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mhiramat@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Hm3bsaZn;       spf=pass
 (google.com: domain of mhiramat@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=mhiramat@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Masami Hiramatsu (Google) <mhiramat@kernel.org>
Reply-To: Masami Hiramatsu (Google) <mhiramat@kernel.org>
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

On Fri, 12 Sep 2025 18:11:12 +0800
Jinchao Wang <wangjinchao600@gmail.com> wrote:

> The new arch_reinstall_hw_breakpoint() function can be used in an
> atomic context, unlike the more expensive free and re-allocation path.
> This allows callers to efficiently re-establish an existing breakpoint.
> 

Looks good to me.

Reviewed-by: Masami Hiramatsu (Google) <mhiramat@kernel.org>

Thanks!

> Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
> ---
>  arch/x86/include/asm/hw_breakpoint.h | 2 ++
>  arch/x86/kernel/hw_breakpoint.c      | 9 +++++++++
>  2 files changed, 11 insertions(+)
> 
> diff --git a/arch/x86/include/asm/hw_breakpoint.h b/arch/x86/include/asm/hw_breakpoint.h
> index aa6adac6c3a2..c22cc4e87fc5 100644
> --- a/arch/x86/include/asm/hw_breakpoint.h
> +++ b/arch/x86/include/asm/hw_breakpoint.h
> @@ -21,6 +21,7 @@ struct arch_hw_breakpoint {
>  
>  enum bp_slot_action {
>  	BP_SLOT_ACTION_INSTALL,
> +	BP_SLOT_ACTION_REINSTALL,
>  	BP_SLOT_ACTION_UNINSTALL,
>  };
>  
> @@ -65,6 +66,7 @@ extern int hw_breakpoint_exceptions_notify(struct notifier_block *unused,
>  
>  
>  int arch_install_hw_breakpoint(struct perf_event *bp);
> +int arch_reinstall_hw_breakpoint(struct perf_event *bp);
>  void arch_uninstall_hw_breakpoint(struct perf_event *bp);
>  void hw_breakpoint_pmu_read(struct perf_event *bp);
>  void hw_breakpoint_pmu_unthrottle(struct perf_event *bp);
> diff --git a/arch/x86/kernel/hw_breakpoint.c b/arch/x86/kernel/hw_breakpoint.c
> index 3658ace4bd8d..29c9369264d4 100644
> --- a/arch/x86/kernel/hw_breakpoint.c
> +++ b/arch/x86/kernel/hw_breakpoint.c
> @@ -99,6 +99,10 @@ static int manage_bp_slot(struct perf_event *bp, enum bp_slot_action action)
>  		old_bp = NULL;
>  		new_bp = bp;
>  		break;
> +	case BP_SLOT_ACTION_REINSTALL:
> +		old_bp = bp;
> +		new_bp = bp;
> +		break;
>  	case BP_SLOT_ACTION_UNINSTALL:
>  		old_bp = bp;
>  		new_bp = NULL;
> @@ -187,6 +191,11 @@ int arch_install_hw_breakpoint(struct perf_event *bp)
>  	return arch_manage_bp(bp, BP_SLOT_ACTION_INSTALL);
>  }
>  
> +int arch_reinstall_hw_breakpoint(struct perf_event *bp)
> +{
> +	return arch_manage_bp(bp, BP_SLOT_ACTION_REINSTALL);
> +}
> +
>  void arch_uninstall_hw_breakpoint(struct perf_event *bp)
>  {
>  	arch_manage_bp(bp, BP_SLOT_ACTION_UNINSTALL);
> -- 
> 2.43.0
> 
> 


-- 
Masami Hiramatsu (Google) <mhiramat@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250914225306.2185b79065e32f60a40ef54c%40kernel.org.
