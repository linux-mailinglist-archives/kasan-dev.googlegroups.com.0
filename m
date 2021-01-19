Return-Path: <kasan-dev+bncBDDL3KWR4EBRB2W3TOAAMGQEQFKVRNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 55FF32FB8BD
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 15:34:21 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id 4sf5050144pgm.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 06:34:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611066860; cv=pass;
        d=google.com; s=arc-20160816;
        b=dQCdP6eyjTeWQLp6QI2M4jSZKG+sk2r43T7bKkrFrEzy3cs/I1PUMPwK9vDgouwZzm
         gB5RKUNP6K9phuPjczuE9L3MYoUBph20U3pK8uxJi7hKuMZdiXqH1c7qxXBR6YPUZzzC
         tHArDYUMkVEdHr52f8Ro6E/kU5QEbi3OqzpFhkuWDECnnVafSvyAN/4qpWvu+ZnScsl5
         attTK4lWmQZ1GEdzYvBEYYWuWiQJWH4R/NfakdQK1RujiQmOHqkHKemYt6Dyxoan5p4e
         58eVAjcjtxm9pKM3roF1BYWnjYgR7Scl08qxdXNH1JrXSV3uUwqpV2JWdN1gqIRl3qnP
         SWhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=OxT+9dn/w4f8cBbXA6rigKRScc91z3OcDI3ic9VD+yg=;
        b=gH8ZqHWCPS1px82zGyAJMOq0dwe9QCEKfVwZq5tHIAhbSqiSbbbXFYL8MpfoCndgwN
         xEpHrlCtE+MumvdOu75bFACKxncaZLV+xrwrMahBd8BzMPWkdVScJo3hnglw6xzlBGIU
         tdX4UZTXyMSW4/tdHvfI72G/UQTHAuE/wQsr3F7y1BVgstspgc9058Yk9vMSysEOHE5K
         Mt2AO5mjb9JcNUQQt/TtaaZjTZA1fgbnSCxyeeBWXSaUU5JLpTyS86SwdlZl1lU2L9Lf
         ZDicJiFwSf1Ce6idRV9rnfKKjVU3I4B8SXcJP1dIVvpRpyyEyOol7408f5DB99V0Yr6v
         TUmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OxT+9dn/w4f8cBbXA6rigKRScc91z3OcDI3ic9VD+yg=;
        b=elNDHtWFTUyhuNew15pbkbvmderlD1lyAnLNFBrVXNKlxcIApLkw6F2JYSN/bje6gc
         venheOvrkhq7x0kuoMXnWMzJT515bk04KIGFj6rVeAInlupb0phovmMFvtB3rCVVnd+T
         Qe2wsHu6qZ88EwU6OW8LcfqK94YIIYo+6MKeclYQeMo2scdeR3SIbEGaQZg+zKlGzSHv
         CDWqf8Dmxu4/kiZ9uz+ccc9ATtkmFOVr0xdaGzk4lurnccp7q7qoCN8gEaz2t3gTxtYI
         beI1+wNoUBQoKLbe2MtS87bQ7gEInISP6ht6UfIkvX3o/TOvJoYFmjiAF7MUOd9AgTI/
         cvUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OxT+9dn/w4f8cBbXA6rigKRScc91z3OcDI3ic9VD+yg=;
        b=t1Um9ge7n7KwNi/6aZIMLn8s7OxjEg+plBHAhqgSkjzZB9ss7U0AQgxBWXWtBcK/h7
         e2iLYDK5Ev51483AiRozrzXB/K6K87og7JOQ8ZPbsKjQQabIcpAlfL7LS7FVJM2HTS9/
         N37f17A6Xqx3uQLbrviq4Tuv119bR6oDdTe7cVo+1G3GP/Svi31qE+cN+koM9z0QV32i
         WjCxX5mo3Rk//IxFc/++2dtcNSgV25Tp3G7XNtGRYQ2ixMqk+oA2+p8eW4u5sCG0y4jC
         QQJJG5YMZFaaTbkFbiqKTPzBLdKO5vWEQrOdF3tRbSk8ZAngTjdqWL3AsX/pIrlG9aZO
         4qpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531bsqElwf/n3UQyb6rj5moONjqVs/fK0nDhtyWIN95AopMwQeUC
	O5XEyh4wfsoZJ/HXF8jEcH8=
X-Google-Smtp-Source: ABdhPJwSw11IPs3Fgp05+wemvdO/b/63hpu/3I4Uvtt/tywFFFzMliEvOUdxXXiYrf08l6u1uMCbDA==
X-Received: by 2002:a17:90a:9e5:: with SMTP id 92mr5850839pjo.176.1611066859072;
        Tue, 19 Jan 2021 06:34:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a416:: with SMTP id p22ls9967686plq.3.gmail; Tue, 19
 Jan 2021 06:34:18 -0800 (PST)
X-Received: by 2002:a17:90a:ad01:: with SMTP id r1mr6000969pjq.197.1611066858449;
        Tue, 19 Jan 2021 06:34:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611066858; cv=none;
        d=google.com; s=arc-20160816;
        b=mFQ9FDm4Q4J/ibRjVouziBWEVTIHJkxk49kY/VY8fQQ4eoso+iKHNjHdxq+5GUKM7C
         JcZQsSvEG2YAutwGt7Wnd0EmgJK9naOCxQMLbqiRBFn/hw1x6cweFIEw6Lenu6Yxzx1N
         29slXkagXB6s4jonIlK1rfT0KCECe/0fMcvhVyHL0KlVKFy8H3/mU2U4qFIoEfwhJUSF
         I+p23QxL/IfUF7VOzhzVVncJHdo1zgzPZxOzX2WAz2U6OuGLQJk/UyhvAK3aM3M8/CBx
         g6LL3pP+y5RKEjUffDpgyu8VOemREwfakYvUszJmrnltDkppJfsRmpyfzvkK3EvU8y5g
         1e/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=9PX5lU930V8ukGTDolKMBVc5R9cVK6OJ4uXlFs/YGlQ=;
        b=p/crUAo9Hv5jhIRLGS1+A1Aw4TLv6nNfqgZLH6izzf+redwlE1er+okj8i0PMA5QKE
         GODO5q5+vfyVRIc01kVXpMrE/3pEds+TM4PVU26muEfUNxWsD27nTQeNkoXNIB4np+PB
         RD6V8v52gLh2bPef2AMo++lNDgIVUoYFMHHbOYbXH6szZw6jXk++S3jxeA3WFz9IRVkH
         yDsvBtpcMn3eoP7LPB3rkdSYXl6EIU47RX05QMTCyqSi2HExSDilW30cHI773Toa3RLJ
         zUvc8KvzSECxrtbVC/6gjkqE0QATLLe3DdZ8F+gK7Hhq8JPiRUKjGWnAkCeai2mMDNeE
         ldzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d7si397357pjg.2.2021.01.19.06.34.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Jan 2021 06:34:18 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 3FA25206E5;
	Tue, 19 Jan 2021 14:34:16 +0000 (UTC)
Date: Tue, 19 Jan 2021 14:34:13 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v4 4/5] arm64: mte: Enable async tag check fault
Message-ID: <20210119143412.GD17369@gaia>
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
 <20210118183033.41764-5-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210118183033.41764-5-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Jan 18, 2021 at 06:30:32PM +0000, Vincenzo Frascino wrote:
>  static void update_sctlr_el1_tcf0(u64 tcf0)
>  {
>  	/* ISB required for the kernel uaccess routines */
> @@ -235,6 +273,15 @@ void mte_thread_switch(struct task_struct *next)
>  	/* avoid expensive SCTLR_EL1 accesses if no change */
>  	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
>  		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
> +
> +	/*
> +	 * Check if an async tag exception occurred at EL1.
> +	 *
> +	 * Note: On the context switch path we rely on the dsb() present
> +	 * in __switch_to() to guarantee that the indirect writes to TFSR_EL1
> +	 * are synchronized before this point.
> +	 */
> +	mte_check_tfsr_el1();
>  }

We need an isb() before mte_check_tfsr_el1() here as well, we only have
a dsb() in __switch_to(). We do have an isb() in update_sctlr_el1_tcf0()
but only if the check passed. Now, it's worth benchmarking how expensive
update_sctlr_el1_tcf0() is (i.e. an SCTLR_EL1 access + isb with
something like hackbench) and we could probably remove the check
altogether. In the meantime, you can add an isb() on the "else" path of
the above check.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210119143412.GD17369%40gaia.
