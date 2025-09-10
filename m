Return-Path: <kasan-dev+bncBD53XBUFWQDBBZM2QTDAMGQE2UBGIAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 30F7EB50D4B
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:32:23 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-329b1e1d908sf2630324fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:32:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757482342; cv=pass;
        d=google.com; s=arc-20240605;
        b=OhqO+kLmFkFWjgGHH2ewc76H/e/xGPk/bAGDxMt2UtUc6yGc7UL9Yus+LW8ILhGMKH
         rvFJJjvhSt74/pIK6wKAQK1EFfiEehD1naaJZdrFE8D7UqnpS0ncLHvGUefFb38SKF4b
         mCRUg8/DKLKrLNhKTL8Oi9ZR1c53TaA0TEHEyOlUzZ14CkvBwAFbRlhXgQzJEpDxGp2A
         MIntgwtOiN6JI2HVo/ECJoCmsI46b0Nua4z7/wYhSzebAwWyAkZ40rpM9rBZlQZMMSyR
         O6beI85L3IgnLReeZCBGwKJUVdtUI8n3rJtzb8oF5cczPQmqMKyhej8aolck0A2q/InI
         I63A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=nmtM7IOytbh4dd0SmUfImNFkz8+E8FdlXZL68Otbnrs=;
        fh=JPWi5CX53AxnKu2btyxGljyRVaQO+srd0bj1Pf1k8O4=;
        b=dibvUL8sLSz9jJkGGHHVKz38xT98CF2OmiNXg2nffcHLaRsPV7a7PuN7mZF5kPUpPC
         WwaGmnYI5ESJaL5gyWhYLcGVIGvbA4HxNvJDHRReUXwEp/I7gkDGrQIqUUNDLjNEmAN3
         jfuhEaHEeUiBMxQTdNehNTPzexeRX8fJdiLohcHDWQf8yhsRK5tX63Z3bqVjvRZKfZMg
         bimqc1348Bm2IN6L6xdXM1qXAO68Bm9dfhhLvGSmMT1Q9Qc3q3jVaRCSIO8BdnA2ftYM
         fjj1glGXEL/E2RH9E66gq2QALFekEJw41Oevwdhml2Hm4PfeSUW7AkwtvmG3A4p7C55Y
         p8Sw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ioFYPxXi;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757482342; x=1758087142; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nmtM7IOytbh4dd0SmUfImNFkz8+E8FdlXZL68Otbnrs=;
        b=Q1E6tE8MziU9ojRhfHw6PqztD0Y2V5dGzbatdwVrTle97nHkr33aDHdTyHUfDmCi8d
         zTwSg+8/D+W05quJL1Vb/3S1Wl7uI72ImliTPOwiMCdfNmVwKCIks7HjCLmIrXkuMlPy
         S3UHJEJ28XUIwRQeHlQ9HEyJkOhcktV69ctjXtTyYsJBShenldxu4CzdOFJczLkgL7Id
         zWuumLIahvNr2HeoMsCCKiUTLDXyDLc0uBtDgAZUDWPIliS4McCSzrtQ5BhZfbz4mZDl
         GmBmCNINSCJuqkK/oYbn0DsN9Qd5c1qGA3DBtbamrWzXvTJkFn04oMaEPgZRLYk8f5/X
         r71Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757482342; x=1758087142; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=nmtM7IOytbh4dd0SmUfImNFkz8+E8FdlXZL68Otbnrs=;
        b=C8dmRT9L9Kq0qj5culkUFhZ7lR4jeBQLANkB+8r2/l0DFHl+ehoTDGQcJp2qM3DUzg
         GpXXDOxiS++0QPrjftk6nEualOYHJC7bdpgLXgMgSfMt+G8AIIEkY6w8xuFtLmyhVM12
         79ptMAzGUUV9nLDjSJbGgRG6eCd5gbgbKR//8jvqoKkCvNbIJb7v0JJ8Od+DMWKB5k4p
         UiqMTzl/0tsllbrYDgsbysfGVPseg3LAiLga0D53p0F4NwaFdvBH/CoYDHdsZc7Vds0j
         SpsqHN2L7OdEEHYVAazE+wpRS8hWjzqcI0sgYRNEzAqAc9WNbZvNnXraweMCtlUwkVmt
         C5rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757482342; x=1758087142;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nmtM7IOytbh4dd0SmUfImNFkz8+E8FdlXZL68Otbnrs=;
        b=V7cmX5W59CDrtrk2nPPOYC/T5QkZuBPJwWMGL3KYSkVqMXbLOwMiIZyr7OU9fwMHF4
         IzASzFLBmlSY/XHIpw7yRgHPk93oFaz3sLFb51AiLXH1utrKVWCyyAkBxdgNbhxn8K28
         Z6uHnS7NRImj/7U/92Q4F+qnNjyAAYaDdfA/9x6bze0GswBBtBX2YPPVYgBu/UZK1Ln9
         21dY2CgmDTVmEhCMGIAgFHLwB+e1/0DoZecm0o2NJf+laLoaM7J+Eu3UB7ShvDLpk6KS
         z2V6vQwTlCCF8490ie3Nn5O8uq22IfEgx7geBz1NGey3r3PWx2TIDpFWGNyaqckXV/Yh
         v9hA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV/k4wT1E4H/U+OYFTvCswSyLH6pnAc4WAypWM6/8lHDHlfF2ooKSwYmMaAs0+5tBNSk86Bxg==@lfdr.de
X-Gm-Message-State: AOJu0YxYKyXGGASEYd5PSu5LIkRIvF9a+jjs+xGmwFz5QhrXVQHqdA5p
	LNIRNLlqXzRvJxqwuIwxjLyyZCMEjkmDUhnGth83F5CZE6mT9v1W6bHm
X-Google-Smtp-Source: AGHT+IH7J6c412+qHjbBpzHdG5tnmhRP8esmYSXNWiAR9Vpf+m95LSre/hgGWeqINItgYREKZT66kQ==
X-Received: by 2002:a05:6870:d95:b0:310:b613:5fd5 with SMTP id 586e51a60fabf-322626446b9mr7715234fac.10.1757482341923;
        Tue, 09 Sep 2025 22:32:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5+a/iGQ198yWhasmFwN8kaTfGOUITBoXzQZLUOBYND+g==
Received: by 2002:a05:6871:c711:b0:319:c528:28df with SMTP id
 586e51a60fabf-321271cc521ls2870095fac.1.-pod-prod-08-us; Tue, 09 Sep 2025
 22:32:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU+b8d/dgGnVNnkFtsRnRcio63si5EGRXLY9/eeFvNpHYmqkScqw83HRVKN/vk49OrihiT+N58w3Ew=@googlegroups.com
X-Received: by 2002:a05:6830:dcc:b0:745:a245:f3c0 with SMTP id 46e09a7af769-74c77b62bb3mr7687514a34.29.1757482340798;
        Tue, 09 Sep 2025 22:32:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757482340; cv=none;
        d=google.com; s=arc-20240605;
        b=aa5HOuthHNozcHP5cLQPvS1075Eidd//mWoC6zveR4qjl9wQcLR3jmqBd7mbgLYMiH
         cmW4ZcAlJUH+uRXC+F/1H3h1XLjoExM2XHZPgw7Xk6XUgo+7v0pm9pphFKOLmVEZvmX3
         /7g4FvPZg7YEOR+FdqO2a9CFUL2G/2RAgxmeHfN2j9ip+d3gGkSMbQvKNbo0VSLrErbG
         Y8WbBwOYcdzax+z8l3MrR4OzIk3uZgrO6aP0CYhk+/6jSKS+IeuHsfNmT28XOkkpzNEG
         LOTWcdEY8tBPUCAkuCZxM7WWMmOb6vKzXIyqfx5hPFMFSs2VhzeEOps9YbUmj3e/YeUU
         hSLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gaYg+/0/ozWnszVW1Vg9icfOKh+UQdPJqj98WeYrJSI=;
        fh=ODXvjls294RbA7hIIdBdgKIfLNTXZXR/dpyPhtNhufM=;
        b=UMLKX61w6QgY3oxOwxAHt5XAXbaG5oDT/1VDZE3WMNQElf77ALFocIZ9DKHLVY7IIN
         KoH9P4u1Jbl96BjkWU7r19BtjZlWt+0EwoystvxzgXpnGXixoQl67jSTIw8mH/RIkwiL
         a+ATj7QEYxwKJxIw5q+IFMARJ+OJkKRIEwVQmyaoNRQLW21xcxLkXFms1xBN/s3YHHOc
         RnOf4rkX7yEO4SkT4CH5VhrxxSGdu7LzTcgDh8QoY+kyVir3ya1arRo2R03+fpRL+jb2
         paeaTts0t5CM7kiXWECZTMyhoeDCapaKzt7F+lfWZtEE2lyQLAlm1zgHKVSjefoYmJw/
         iXOQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ioFYPxXi;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-745a33b347asi692883a34.3.2025.09.09.22.32.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 22:32:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id d2e1a72fcca58-772301f8a4cso8965680b3a.3
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 22:32:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWh3BlAdFBPiAwtNoeUH/vDxtv8uSbGXnwjOSs8gqBWBc6CwLzvdUV0dAeLgQ1HXPiGQCXZrWt62uU=@googlegroups.com
X-Gm-Gg: ASbGncs1D7gT93Wtp9fB6PIARP3d1qMAa+pzsLkPeEjyebpnVsHLnzEwRtSyTwwUjgT
	MbvjV48d8DH/7HBGwlM6GRaXysDQo+P3d8OPBttBEzAJjFJiK1hdymvRdDZvXPzhaX07AJJQZv8
	Pjxs7k7fac4E9IGEK2cSrdpM7Hr6jG8cC7x2w3rDGaj6hO+pMt84FWKya8KPt25INgg3U1jPsdW
	VMPSnJcucfzRnj7WQhZaPx+y46Rbh2QN0IFUB+louhTTu+XE1zJfrrq6Vkk2hWBtwY9Ydi/CXoo
	Kry+Bt5QT6F85EI/mxERfzKIqjB3PTzETEmoPivP10BGCLu76+ijxNRH4e0nCM/OV9a4Ci0k0Du
	ghA7pze3XSDp0kOlq073yInoTG9Yj5ETjZ3HQe1p6J2me/RblBw==
X-Received: by 2002:a05:6a00:1a8f:b0:772:2850:783d with SMTP id d2e1a72fcca58-7742dedf06emr18816777b3a.22.1757482339803;
        Tue, 09 Sep 2025 22:32:19 -0700 (PDT)
Received: from localhost.localdomain ([45.8.220.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7746628ffbesm3870342b3a.66.2025.09.09.22.32.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:32:19 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	"Naveen N . Rao" <naveen@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"David S. Miller" <davem@davemloft.net>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	linux-mm@kvack.org,
	linux-trace-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org
Cc: linux-kernel@vger.kernel.org,
	Jinchao Wang <wangjinchao600@gmail.com>
Subject: [PATCH v3 10/19] mm/ksw: resolve stack watch addr and len
Date: Wed, 10 Sep 2025 13:31:08 +0800
Message-ID: <20250910053147.1152253-2-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250910053147.1152253-1-wangjinchao600@gmail.com>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
 <20250910053147.1152253-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ioFYPxXi;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add helpers to find the stack canary or a local variable addr and len
for the probed function based on ksw_get_config(). For canary search,
limits search to a fixed number of steps to avoid scanning the entire
stack. Validates that the computed address and length are within the
kernel stack.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/stack.c | 86 ++++++++++++++++++++++++++++++++++++++++--
 1 file changed, 83 insertions(+), 3 deletions(-)

diff --git a/mm/kstackwatch/stack.c b/mm/kstackwatch/stack.c
index 72409156458f..3ea0f9de698e 100644
--- a/mm/kstackwatch/stack.c
+++ b/mm/kstackwatch/stack.c
@@ -13,14 +13,94 @@ static struct kprobe entry_probe;
 static struct fprobe exit_probe;
 #define INVALID_PID -1
 static atomic_t ksw_stack_pid = ATOMIC_INIT(INVALID_PID);
+#define MAX_CANARY_SEARCH_STEPS 128
+
+static unsigned long ksw_find_stack_canary_addr(struct pt_regs *regs)
+{
+	unsigned long *stack_ptr, *stack_end, *stack_base;
+	unsigned long expected_canary;
+	unsigned int i;
+
+	stack_ptr = (unsigned long *)kernel_stack_pointer(regs);
+
+	stack_base = (unsigned long *)(current->stack);
+
+	// TODO: limit it to the current frame
+	stack_end = (unsigned long *)((char *)current->stack + THREAD_SIZE);
+
+	expected_canary = current->stack_canary;
+
+	if (stack_ptr < stack_base || stack_ptr >= stack_end) {
+		pr_err("Stack pointer 0x%lx out of bounds [0x%lx, 0x%lx)\n",
+		       (unsigned long)stack_ptr, (unsigned long)stack_base,
+		       (unsigned long)stack_end);
+		return 0;
+	}
+
+	for (i = 0; i < MAX_CANARY_SEARCH_STEPS; i++) {
+		if (&stack_ptr[i] >= stack_end)
+			break;
+
+		if (stack_ptr[i] == expected_canary) {
+			pr_debug("canary found i:%d 0x%lx\n", i,
+				 (unsigned long)&stack_ptr[i]);
+			return (unsigned long)&stack_ptr[i];
+		}
+	}
+
+	pr_debug("canary not found in first %d steps\n",
+		 MAX_CANARY_SEARCH_STEPS);
+	return 0;
+}
+
+static int ksw_stack_validate_addr(unsigned long addr, size_t size)
+{
+	unsigned long stack_start, stack_end;
+
+	if (!addr || !size)
+		return -EINVAL;
+
+	stack_start = (unsigned long)current->stack;
+	stack_end = stack_start + THREAD_SIZE;
+
+	if (addr < stack_start || (addr + size) > stack_end)
+		return -ERANGE;
+
+	return 0;
+}
 
 static int ksw_stack_prepare_watch(struct pt_regs *regs,
 				   const struct ksw_config *config,
 				   u64 *watch_addr, u64 *watch_len)
 {
-	/* implement logic will be added in following patches */
-	*watch_addr = 0;
-	*watch_len = 0;
+	u64 addr;
+	u64 len;
+
+	/* Resolve addresses for all active watches */
+	switch (ksw_get_config()->type) {
+	case WATCH_CANARY:
+		addr = ksw_find_stack_canary_addr(regs);
+		len = sizeof(unsigned long);
+		break;
+
+	case WATCH_LOCAL_VAR:
+		addr = kernel_stack_pointer(regs) +
+		       ksw_get_config()->local_var_offset;
+		len = ksw_get_config()->local_var_len;
+		break;
+
+	default:
+		pr_err("Unknown watch type %d\n", ksw_get_config()->type);
+		return -EINVAL;
+	}
+
+	if (ksw_stack_validate_addr(addr, len)) {
+		pr_err("invalid stack addr:0x%llx len :%llu\n", addr, len);
+		return -EINVAL;
+	}
+
+	*watch_addr = addr;
+	*watch_len = len;
 	return 0;
 }
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910053147.1152253-2-wangjinchao600%40gmail.com.
