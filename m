Return-Path: <kasan-dev+bncBCALX3WVYQORBUEY5P4QKGQERVW25YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CF46247179
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Aug 2020 20:28:34 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id g3sf8089688otq.7
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Aug 2020 11:28:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597688913; cv=pass;
        d=google.com; s=arc-20160816;
        b=zIJ2SCAxlJXi06JzaiyOwmCxN3Ofq0WqFWLfN3T+psrGom/bQ++52llk7c3mTCfXsg
         jinLjPfoQsTxhKGcFtQWQ83zGkBGMvinTaZoBZW27Vj46sKg5UkCLduIlvoxEKt/JTmb
         U7lW2woLukXfH/cOceoyGVV6ANQN9Sxb29OfYh+WgBBxJDL0aPm4Sguxu21vgYEWWsDv
         qlYMc9lVSc/IXLIMWJw4bUT78doe3e+Yy1k5DtAonsf82do2X+zGEP1afhClr0lCfkLj
         WXDYQ0/UYnqGR+9L1yBHMatGYCX4YrP6gyinA66QO7Xtvo9Qbh7RcqHYq1fSn31N8rR1
         o6Ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=iDDrrprHrI4S3jjgS1RpgBqth+Fmk6KIcCJnJVcE6qQ=;
        b=V6V7J4Rrm1OLXk1tJV4oSlu1N0GWP/KPaoqMF8ZHnN1IqMXKJTBccoJ83APb1jRF4M
         mfoB2XyCQ79QbSBaXDo4K6NJQea1nVE4YZ2v52eexptVo90G7ks8TNeL072Jv0bxBmyn
         B9V4V0VIyWUjt1AZR1vnUgPiMRinXSqLw4xUlhyzbGavtfQbHGRbw4j7hHjCEc5+ZjGp
         mtX655OzD00j9fLCAIN9TvzoQJTDMaQnUJNdURjpEuCtQQDHm4bKNzixbUFULpQafHbu
         zknXRqsmrz2Trav0kDaOwGKC2rPWQHdU7CqOaE8Rqiko/+Dr7X5TJGX2+kQ2IaG3zdPM
         bGiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iDDrrprHrI4S3jjgS1RpgBqth+Fmk6KIcCJnJVcE6qQ=;
        b=qM1gEdAfZzGNG+MmgSaYdD1y1H4kVlq5nTd6x/uNZ8hKpeUHjw5s7ZO+cP6aUA1V8q
         EGRrso7csQLhU893WGnyzSSEZD/ixX1T5yyBzimB7/ZpqKuh9tcsEfru+fmj4SIiRqn1
         hC4Cy6XWDYxAZsrAPcD9JiWu0ebQSb4gWy7ClKmOPPtLsh8fmLrc+fP1g0S9TtIRaSGb
         gTFtrfSs7+So28St3ywHpDBpFgaUHnAacxdymae+RSs7KWojZNl0VQwrpQllMiCt08Qb
         F2FtKVJmfuU9CU4CYPQtgbuJnhG8qlziQEyqmtKpg6n+Pi9qVAf7mBBiRRQNlD4ilK/A
         xEFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iDDrrprHrI4S3jjgS1RpgBqth+Fmk6KIcCJnJVcE6qQ=;
        b=H6vx9y+Of63BAJzE+4Q2KNX+ni6gJvSN6kHubGcauzv+99q2ux2+BR36uRlT0TfbdV
         HtSP9PjXxQSNzhyodSGYCq6Gaea0yUaANEkfJSfiJE+2RTb/wck6R0Vogi6m6cBWvtNp
         dGZne8O74P9aDQz5JWa8LQo4/h+jQmHvNTuP4KKLvCGQJcggCZThUEDMD6cSB7bqTTy6
         zjV7CM4MdEnhuBagSW1v8kC0BtoPgu5tdrmAl4sdHpWbI2K1tt2Bm8vugUHsYVN7inJv
         KGqFM0g35GeWIYLkdeclJAEC2Kjwsyii934MaLZkqEzVTJNCgQhZ79c7HF2JNMn/K/e5
         GuSQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531UaqVGuHs77eDbOs+RyfWYVhjwCpme+M4z13ydBzknKqo3o+5M
	GxLsJ5TlazYNRfL1gkg24Bs=
X-Google-Smtp-Source: ABdhPJx40ylFJ03j0MbaDTLQ2X4FWcvS2aPapc9ac20ioWFKgqZez+NDmRMrfIj8Ffxfju6k8l9ZfA==
X-Received: by 2002:a05:6808:b03:: with SMTP id s3mr10608266oij.154.1597688912805;
        Mon, 17 Aug 2020 11:28:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:42c5:: with SMTP id p188ls3514611oia.3.gmail; Mon, 17
 Aug 2020 11:28:32 -0700 (PDT)
X-Received: by 2002:aca:5857:: with SMTP id m84mr10225892oib.59.1597688912493;
        Mon, 17 Aug 2020 11:28:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597688912; cv=none;
        d=google.com; s=arc-20160816;
        b=bniM6WA7SYIev6nfhq+CZ2wjQvFQ6K504vIXDcgcCeqz0g9Wk6hROFcLpE4lsfhK2q
         jCgkuDZnsQ5MGKIgttm2Y584kRiEO7kHIYN1R0XhRwomR/D8tix89AmM5lbu0vMLef7l
         QqzS2+/3l7ZIStfmth6BJ3ZhiJPuq258r4lcclvh1sYVmSZbrC22KwDmXL/73TqsmEzv
         FfZwoNUaSYEDe/UqNrLe2jZS2Et0IBOTEzb7QeA85IEgt8/OyqWlTGuVGDtnid8vfQsy
         JdyUPiYLQHFWN21f8KEFh/gewEq34/dDQ/6JvHm/NiRxMyLonrIR3gme+ihrjf/SsfLB
         N/pA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=VBqKzsLDMaW2ERJxaGSqalEzujrBfb0P1g5Ju4X/8uo=;
        b=otGsk533vBuKAbx58XQg+luY+z4tpbMH0yCNGMMfZVzQP+Atx1akGVhS/zTCZfb6GZ
         f7gaNGAcSarg/xQOJFAWqJXJ0qFKQVq+/mnmAsOMpppCqpmOgjQsRN5fJo8O9vJ0qtmw
         4/+kBIED2rUjCwm28GCQF/y+J91K640wzwE5wN838Dk3lQdx8OPtiqNkLnDuLMEPE0bh
         9eGUsde1RvLSi5ATh5qmp5Qu6ghbB48DC5WDogShtTV0xNaKZOhy5sWAHaVrVRgCsgGQ
         dsgbMf5IDk+MrdTJAHwEKTziJnWeSNdGJPaEsejiUPNj8AelzbdmAd/EHy19JcPze2kg
         hK1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id 22si1017694oiy.5.2020.08.17.11.28.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Aug 2020 11:28:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out02.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1k7jrk-001UEg-5B; Mon, 17 Aug 2020 12:28:16 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=x220.xmission.com)
	by in02.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1k7jrj-0003E9-5O; Mon, 17 Aug 2020 12:28:15 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Alexander Popov <alex.popov@linux.com>
Cc: Kees Cook <keescook@chromium.org>,  Jann Horn <jannh@google.com>,
 Will Deacon <will@kernel.org>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>,  Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Masahiro Yamada <masahiroy@kernel.org>,
 Masami Hiramatsu <mhiramat@kernel.org>,
 Steven Rostedt <rostedt@goodmis.org>,
 Peter Zijlstra <peterz@infradead.org>,
 Krzysztof Kozlowski <krzk@kernel.org>,
 Patrick Bellasi <patrick.bellasi@arm.com>,
 David Howells <dhowells@redhat.com>,
 Johannes Weiner <hannes@cmpxchg.org>,
 Laura Abbott <labbott@redhat.com>,  Arnd Bergmann <arnd@arndb.de>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 kasan-dev@googlegroups.com,  linux-mm@kvack.org,
 kernel-hardening@lists.openwall.com,  linux-kernel@vger.kernel.org,
 notify@kernel.org, Kexec Mailing List <kexec@lists.infradead.org>
References: <20200813151922.1093791-1-alex.popov@linux.com>
	<20200813151922.1093791-3-alex.popov@linux.com>
Date: Mon, 17 Aug 2020 13:24:37 -0500
In-Reply-To: <20200813151922.1093791-3-alex.popov@linux.com> (Alexander
	Popov's message of "Thu, 13 Aug 2020 18:19:22 +0300")
Message-ID: <87zh6t9llm.fsf@x220.int.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1k7jrj-0003E9-5O;;;mid=<87zh6t9llm.fsf@x220.int.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1+IYzzebB5ZnTtqYaH62lkbTUMdTHJJuM0=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa03.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=0.5 required=8.0 tests=ALL_TRUSTED,BAYES_40,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,XMNoVowels autolearn=disabled
	version=3.4.2
X-Spam-Virus: No
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	* -0.0 BAYES_40 BODY: Bayes spam probability is 20 to 40%
	*      [score: 0.3847]
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa03 0; Body=1 Fuz1=1 Fuz2=1]
X-Spam-DCC: ; sa03 0; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ;Alexander Popov <alex.popov@linux.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 567 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 3.6 (0.6%), b_tie_ro: 2.4 (0.4%), parse: 1.22
	(0.2%), extract_message_metadata: 14 (2.5%), get_uri_detail_list: 2.4
	(0.4%), tests_pri_-1000: 9 (1.5%), tests_pri_-950: 1.47 (0.3%),
	tests_pri_-900: 1.36 (0.2%), tests_pri_-90: 236 (41.6%), check_bayes:
	226 (39.9%), b_tokenize: 16 (2.7%), b_tok_get_all: 59 (10.4%),
	b_comp_prob: 3.1 (0.5%), b_tok_touch_all: 145 (25.6%), b_finish: 0.71
	(0.1%), tests_pri_0: 290 (51.1%), check_dkim_signature: 0.41 (0.1%),
	check_dkim_adsp: 2.0 (0.4%), poll_dns_idle: 0.76 (0.1%), tests_pri_10:
	1.72 (0.3%), tests_pri_500: 5.0 (0.9%), rewrite_mail: 0.00 (0.0%)
Subject: Re: [PATCH RFC 2/2] lkdtm: Add heap spraying test
X-Spam-Flag: No
X-SA-Exim-Version: 4.2.1 (built Thu, 05 May 2016 13:38:54 -0600)
X-SA-Exim-Scanned: Yes (on in02.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as
 permitted sender) smtp.mailfrom=ebiederm@xmission.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=xmission.com
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

Alexander Popov <alex.popov@linux.com> writes:

> Add a simple test for CONFIG_SLAB_QUARANTINE.
>
> It performs heap spraying that aims to reallocate the recently freed heap
> object. This technique is used for exploiting use-after-free
> vulnerabilities in the kernel code.
>
> This test shows that CONFIG_SLAB_QUARANTINE breaks heap spraying
> exploitation technique.
>
> Signed-off-by: Alexander Popov <alex.popov@linux.com>

Why put this test in the linux kernel dump test module?

I have no problem with tests, and I may be wrong but this
does not look like you are testing to see if heap corruption
triggers a crash dump.  Which is what the rest of the tests
in lkdtm are about.  Seeing if the test triggers successfully
triggers a crash dump.

Eric

> ---
>  drivers/misc/lkdtm/core.c  |  1 +
>  drivers/misc/lkdtm/heap.c  | 40 ++++++++++++++++++++++++++++++++++++++
>  drivers/misc/lkdtm/lkdtm.h |  1 +
>  3 files changed, 42 insertions(+)
>
> diff --git a/drivers/misc/lkdtm/core.c b/drivers/misc/lkdtm/core.c
> index a5e344df9166..78b7669c35eb 100644
> --- a/drivers/misc/lkdtm/core.c
> +++ b/drivers/misc/lkdtm/core.c
> @@ -126,6 +126,7 @@ static const struct crashtype crashtypes[] = {
>  	CRASHTYPE(SLAB_FREE_DOUBLE),
>  	CRASHTYPE(SLAB_FREE_CROSS),
>  	CRASHTYPE(SLAB_FREE_PAGE),
> +	CRASHTYPE(HEAP_SPRAY),
>  	CRASHTYPE(SOFTLOCKUP),
>  	CRASHTYPE(HARDLOCKUP),
>  	CRASHTYPE(SPINLOCKUP),
> diff --git a/drivers/misc/lkdtm/heap.c b/drivers/misc/lkdtm/heap.c
> index 1323bc16f113..a72a241e314a 100644
> --- a/drivers/misc/lkdtm/heap.c
> +++ b/drivers/misc/lkdtm/heap.c
> @@ -205,6 +205,46 @@ static void ctor_a(void *region)
>  static void ctor_b(void *region)
>  { }
>  
> +#define HEAP_SPRAY_SIZE 128
> +
> +void lkdtm_HEAP_SPRAY(void)
> +{
> +	int *addr;
> +	int *spray_addrs[HEAP_SPRAY_SIZE] = { 0 };
> +	unsigned long i = 0;
> +
> +	addr = kmem_cache_alloc(a_cache, GFP_KERNEL);
> +	if (!addr) {
> +		pr_info("Unable to allocate memory in lkdtm-heap-a cache\n");
> +		return;
> +	}
> +
> +	*addr = 0x31337;
> +	kmem_cache_free(a_cache, addr);
> +
> +	pr_info("Performing heap spraying...\n");
> +	for (i = 0; i < HEAP_SPRAY_SIZE; i++) {
> +		spray_addrs[i] = kmem_cache_alloc(a_cache, GFP_KERNEL);
> +		*spray_addrs[i] = 0x31337;
> +		pr_info("attempt %lu: spray alloc addr %p vs freed addr %p\n",
> +						i, spray_addrs[i], addr);
> +		if (spray_addrs[i] == addr) {
> +			pr_info("freed addr is reallocated!\n");
> +			break;
> +		}
> +	}
> +
> +	if (i < HEAP_SPRAY_SIZE)
> +		pr_info("FAIL! Heap spraying succeed :(\n");
> +	else
> +		pr_info("OK! Heap spraying hasn't succeed :)\n");
> +
> +	for (i = 0; i < HEAP_SPRAY_SIZE; i++) {
> +		if (spray_addrs[i])
> +			kmem_cache_free(a_cache, spray_addrs[i]);
> +	}
> +}
> +
>  void __init lkdtm_heap_init(void)
>  {
>  	double_free_cache = kmem_cache_create("lkdtm-heap-double_free",
> diff --git a/drivers/misc/lkdtm/lkdtm.h b/drivers/misc/lkdtm/lkdtm.h
> index 8878538b2c13..dfafb4ae6f3a 100644
> --- a/drivers/misc/lkdtm/lkdtm.h
> +++ b/drivers/misc/lkdtm/lkdtm.h
> @@ -45,6 +45,7 @@ void lkdtm_READ_BUDDY_AFTER_FREE(void);
>  void lkdtm_SLAB_FREE_DOUBLE(void);
>  void lkdtm_SLAB_FREE_CROSS(void);
>  void lkdtm_SLAB_FREE_PAGE(void);
> +void lkdtm_HEAP_SPRAY(void);
>  
>  /* lkdtm_perms.c */
>  void __init lkdtm_perms_init(void);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87zh6t9llm.fsf%40x220.int.ebiederm.org.
