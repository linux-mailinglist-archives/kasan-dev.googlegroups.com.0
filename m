Return-Path: <kasan-dev+bncBDDL3KWR4EBRBLOO7CPQMGQEIMPR4II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id E2EFA6A5CCA
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 17:09:18 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id g21-20020a2e9cd5000000b00295cbacaf20sf694924ljj.14
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 08:09:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677600558; cv=pass;
        d=google.com; s=arc-20160816;
        b=R8DhIBd2T8PjhUGg5vlXhk+THs1OiMp1GqM7h3pTmU2ADI+zQxEnk/k7MOqOEt+7N4
         pPIJaZGFXc3EHIVYkxmdQDCJW54J4tC1hKwhmv2GjmqT0YfSQrh6hQCtgm2dZAr4UUWJ
         oe18i+120/guvSU1j/+xjhlEfKNoKzdGoXh5Y1gDMaSzuo8WOZ1hgdSbhw2CN9bZjfIW
         i1brkS593Sk+ocah1oUXrhVgf0U4zTZughCDVClatpW8JDGw6sTsEH4iOcHOC249ZOS/
         b19/2HzBGWMUHV8szdrzNKVWtWbOJlMUk+6+KSiFi+1343DFvSBA1I4cKcer+CutkZp6
         a8ZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=M0ZHN9cGQQKE6XeVFPmBRZSK01TK6NszNqjEInKX7sA=;
        b=U8o1CYl+0DwCNl4YMRKmb4qM2gyWmgu0FSilVUAAeZzp51k4yUUqk4jtZ5EwYDbS5p
         LFwHQkpLSG1UuhdXFheaKw797Ims7c8XgxC53bF7gpX6sHi8Cjm/8LbQxELLpsntuyoK
         je3bC70/Ic3eXbeBLT0GQDs63isJ0QpD7GMzD/sekbKvv1AIs7OLyGPc5LdAi3ww39PB
         NqPQzdmygmTyNwJ4FL/KrSLQ0Tm9lruhUvBt4wpBFMVSzuTg2lY0WkrdpFEiwvRqneC4
         rtWDZkV8MOFPtc+BsSrySwyBf/tcFiLBc4dmqoSDq7cwyDDtX0emUmi9GboS9P4SLieV
         A9Bw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=M0ZHN9cGQQKE6XeVFPmBRZSK01TK6NszNqjEInKX7sA=;
        b=hQ1L0zLKqH7ywZBsB8n+N9XPzTPaj0/EKvfNM1vXHPMKC3iG2PfoB986sLNe4q87mb
         kH8h09f/wSOiHesV/QMTFblcVZs4TyxTCHKa78CT4rC7OgZyiQQBbXtw4kHbDXytJ2Y4
         33FDaLYrhWtofAWf4N/8tijgJek4hYpvVPefW0tvrLROP+XtbwQEcGl/mRtmdqLap3Rk
         +v+9GjegCFVafDd/RmPKnuZZm+sOGArN9mMUwq6ZNlzj4eVxOaYaU3ODGjqQmR/9hF2S
         lAsNdIeQZFN0TUvmIurAyVoQGseGMZlWn6ttlmLS8X+SnbD2PuR7Tvw7w+cHR1PydUBL
         OEEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=M0ZHN9cGQQKE6XeVFPmBRZSK01TK6NszNqjEInKX7sA=;
        b=AGP/EHD9lQbL41kMxvkIp8q+IOeggZ/hqywoX7Gljct195ovbDlGAXr2EDZZTNnHiy
         U0ceXxjfePdyW+vYUzsON8O2lv5c7IkEC2CZa5RoRqmTuhFZYsAcZPPq43BIKd0xqyyE
         iq7+aeNpvnOXCN/JQLFEz2TFi7RLuF53lf0th3JmD1BRSv4i3YftlmM91m66NOmD6SlK
         Fx45/O5Iknr3QkyZQpqe2ubmzdcNpdT7wYosrRIDBb7wV+JO/P8hTZKVT81nmHUjlmH0
         qg1NlvRNnVQsS2JXCQ9dhn1/Zkia/RJfYo0uu2JI8a/0fFqTt+ImUX7hAKdhAFEsj0B0
         vYbQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKX52H+UGXbOnRJ1eUuKRQjrXup875DUC9mhpHI3lDQ+Wp1uDXF9
	zKNuCMmDexVr/8SE4cvYrqk=
X-Google-Smtp-Source: AK7set+kZh+4jHX4aOYrF52Hq/wgdrE2oxtS2Fy3XbG+WNGSOfmhsQ7yaQA6lV2UXl7PkbwogykwxA==
X-Received: by 2002:ac2:46f3:0:b0:4dd:a4c5:2b42 with SMTP id q19-20020ac246f3000000b004dda4c52b42mr886236lfo.8.1677600557986;
        Tue, 28 Feb 2023 08:09:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:4024:b0:4dd:8403:13fe with SMTP id
 br36-20020a056512402400b004dd840313fels2871334lfb.3.-pod-prod-gmail; Tue, 28
 Feb 2023 08:09:16 -0800 (PST)
X-Received: by 2002:ac2:46f6:0:b0:4dd:cbf3:e981 with SMTP id q22-20020ac246f6000000b004ddcbf3e981mr790569lfo.28.1677600556210;
        Tue, 28 Feb 2023 08:09:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677600556; cv=none;
        d=google.com; s=arc-20160816;
        b=yjwCvWobPySh1ddNdbcnXICt+0tr3IP4UTmMj3ftk/+DnX//bDYbOQTXKGL6vjJ3WQ
         zu0QoXJkq2cwwdrL1/7PUYkzHaN/KeqoDm3HXkao1CK9HEh0eIaJEcwrBkcWkwOThS1+
         0NbFXszpl48fkpAcEuXJjX8I//jtLmcPg2nRSMoou57WvW51e3nQPTwmsjll4BIfBOK1
         2abs+9GcnOqO7xkU4+I3Uf2RqxzqVSqznhGEqBFm61r2UN1SHDDhVdQsIMcWh+I9VyK/
         3Ng50ss7h1N93ijWcmfK6qxW+EGGVJticY0/wh57dqXsLrkEfjNYDMgwuHOmKy0Wn+pc
         X78Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=xVRqg4B/UzHVPFSnRx9z9t5fF49CuruhZsvJxewuLHo=;
        b=XBH7puDN8Fuw7kbvlsr6U2747Q8m6UMcpM08wY+3u5mybG2kJjeoLmwRNdUCLn4cxK
         qnIkN+9daLOMCjLyMuzH80wnslokXyuD+PSJcfPp9zv0634d8WMCs9LssT6uKjxdktiy
         +r6wHMabPQ7v9SZ9aXfyBScXVfraYRHJIVVPGqZI138xWVfcTVdua0j7ylX4tfLXOjFN
         aoEOMU3LkxXzv1hnYf2OJddfJRd5oNJ2Ql2CJK66HLbzWuSvkQn2rgl2WWPYehee2Y5H
         HbGdOnr9rv8IfI3Ssebl6ZGIDSgkSl/Y8y2S/uZMLcLztG/0PR741XPbXYseQ3QP9CoZ
         kTRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id f9-20020ac24989000000b004dc818e448asi477231lfl.3.2023.02.28.08.09.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 Feb 2023 08:09:16 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 74154B80DDF;
	Tue, 28 Feb 2023 16:09:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B4F14C4339C;
	Tue, 28 Feb 2023 16:09:11 +0000 (UTC)
Date: Tue, 28 Feb 2023 16:09:08 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: =?utf-8?B?6KKB5biFKFNodWFpIFl1YW4p?= <yuanshuai@zeku.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	=?utf-8?B?5qyn6Ziz54Kc6ZKKKFdlaXpoYW8gT3V5YW5nKQ==?= <ouyangweizhao@zeku.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	Weizhao Ouyang <o451686892@gmail.com>,
	=?utf-8?B?5Lu756uL6bmPKFBlbmcgUmVuKQ==?= <renlipeng@zeku.com>,
	Peter Collingbourne <pcc@google.com>
Subject: Re: [PATCH v2] kasan: fix deadlock in start_report()
Message-ID: <Y/4nJEHeUAEBsj6y@arm.com>
References: <20230209031159.2337445-1-ouyangweizhao@zeku.com>
 <CACT4Y+Zrz4KOU82jjEperYOM0sEp6TCmgse4XVMPkwAkS+dXrA@mail.gmail.com>
 <93b94f59016145adbb1e01311a1103f8@zeku.com>
 <CACT4Y+a=BaMNUf=_suQ5or9=ZksX2ht9gX8=XBSDEgHogyy3mg@mail.gmail.com>
 <CA+fCnZf3k-rsaOeti0Q7rqkmvsqDb2XxgxOq6V5Gqp6FGLH7Yg@mail.gmail.com>
 <b058a424e46d4f94a1f2fdc61292606b@zeku.com>
 <2b57491a9fab4ce9a643bd0922e03e73@zeku.com>
 <CA+fCnZcirNwdA=oaLLiDN+NxBPNcA75agPV1sRsKuZ0Wz6w_hQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZcirNwdA=oaLLiDN+NxBPNcA75agPV1sRsKuZ0Wz6w_hQ@mail.gmail.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Feb 27, 2023 at 03:13:45AM +0100, Andrey Konovalov wrote:
> +Catalin, would it be acceptable to implement a routine that disables
> in-kernel MTE tag checking (until the next
> mte_enable_kernel_sync/async/asymm call)? In a similar way an MTE
> fault does this, but without the fault itself. I.e., expose the part
> of do_tag_recovery functionality without report_tag_fault?

I don't think we ever re-enable MTE after do_tag_recovery(). The
mte_enable_kernel_*() are called at boot. We do call
kasan_enable_tagging() explicitly in the kunit tests but that's a
controlled fault environment.

IIUC, the problem is that the kernel already got an MTE fault, so at
that point the error is not really recoverable. If we want to avoid a
fault in the first place, we could do something like
__uaccess_enable_tco() (Vincenzo has some patches to generalise these
routines) but if an MTE fault already triggered and MTE is to stay
disabled after the reporting anyway, I don't think it's worth it.

So I wonder whether it's easier to just disable MTE before calling
report_tag_fault() so that it won't trigger additional faults:

diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index f4cb0f85ccf4..1449d2bc6f10 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -329,8 +329,6 @@ static void do_tag_recovery(unsigned long addr, unsigned long esr,
 			   struct pt_regs *regs)
 {
 
-	report_tag_fault(addr, esr, regs);
-
 	/*
 	 * Disable MTE Tag Checking on the local CPU for the current EL.
 	 * It will be done lazily on the other CPUs when they will hit a
@@ -339,6 +337,8 @@ static void do_tag_recovery(unsigned long addr, unsigned long esr,
 	sysreg_clear_set(sctlr_el1, SCTLR_EL1_TCF_MASK,
 			 SYS_FIELD_PREP_ENUM(SCTLR_EL1, TCF, NONE));
 	isb();
+
+	report_tag_fault(addr, esr, regs);
 }
 
 static bool is_el1_mte_sync_tag_check_fault(unsigned long esr)

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y/4nJEHeUAEBsj6y%40arm.com.
