Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBWQUCWQMGQEDV2XWFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F66A830D38
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jan 2024 20:18:32 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2ccc360edc4sf103000361fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jan 2024 11:18:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705519111; cv=pass;
        d=google.com; s=arc-20160816;
        b=K/wTH1slARqPZs6OpRVmrqOYykwNtF25dhL6oLvAosHAVUnKz1HEOF7hz2fujHMRmN
         85Fh5HpR7wgn5oMzdBMSPqJwScT2VKSoybMeGNS5YS3F61NdrytedKgr7pfRA/L1jMnb
         uC+rpPDp83dZQx/1R8IQBOsdBDQN6fY6qQXp13WD4Zy4ZZlBK9Sy+HKlBuBiRFu34Kca
         KjP5r2y0hjnLALdMtIFvvKJ58w+qlIIKpW40cBkAA+hv21Ez/jYTuy1AOF7z4zfQJo+V
         gwKimAvGlfcjVnUh0RBF/Rdfiv2iXSu0FKR0exxXUyUkBWovMBBQ2PwE7U6BvqyNHOmq
         J9Zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Llwv9KDeb9hBDU5iGiID+4tkuHW98rLDNQZDMZfyrJc=;
        fh=SaMKD/qpL3nGMJUrmiYLa5wMkbVnPqsoNrm4W3W8Cyc=;
        b=0X/1s7NkvFl0x0oVSROFgJpQPgmlYqub+tLtFUHFL+Te8XlqZKJtYKFIBBTzTB2itu
         NiHKFcPmdd2ICt+d7gFQR0MXneGUlprWzfUKwvKNbP+MCzh7D9u+dxDrgtr76EfQdGL1
         FyzD9DM5YnRkdhFN/WW7qE/Zb6l5rUH+SG+hkeXljwpbetWTdLyhSfLiVnZuFyO+D9Mf
         rxtVDSiHlbgYnbpJdODNUJ9xVqMyZBxGHw2Zn1+NB9HLKbXChTLhISZBwDRHiNz42OKe
         w5FQwlETeYvDDPYBwMNWfTaPDiddTqwBoyAYDg/yaevbzBnt5DwE88DtYmpmW4CPsqMa
         UwcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=K7nzuLcd;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705519111; x=1706123911; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Llwv9KDeb9hBDU5iGiID+4tkuHW98rLDNQZDMZfyrJc=;
        b=bHosAVy0aq77Yk9DV0aB0LugB8jmoaQBJz3xPs+bL9O+WU33v+tMMFh7oy32hqkFHs
         +dp8WrvoPfWFphI705OfOs3wGxWqFwLWiGuC4Emh65BsiciA/joDgH3qUvoCn/zzxGPv
         g18x3G2nXcUUTc3utc3zGc+9fl/FdzkLCSYDr+p3XdgU6FfqHMYcuZTHHbpgRfByU/yR
         mWUG33tDLlscwYb+YdhqTlpFMz7sSs2Ss9Cv2pvjwFVimh44ererGHOwQlE/a9/6EbRL
         b5BuesoH2P+ijj2sMNE/UeWP3qqPvIGrXqNW24g5XB9BW7/lMmt0ShbF27PAC/v7m+ro
         V8/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705519111; x=1706123911;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Llwv9KDeb9hBDU5iGiID+4tkuHW98rLDNQZDMZfyrJc=;
        b=g0oBXuij2553xL5nt4eYXt0SvGHsTIlNuJhkmm+hQyN8+PGrkg92HQC4yx47DvNBUc
         fy6MjdgOtJfom5DfXv5m2hvqeVk7YolSbwOPmCH45H8y9VLVZ0C0LGfsSbXfFymbEJIk
         eUQxCa4sBU9GcF+K3eTvenZWG/g20XJfF9uDuaFg1SxKFUic/3F7YlSak7n6xH+w7ZvM
         44lh21qoYNQVq4jF1eHhB27hKNBFtWZdE2KpNXZLqt+lbe5KSWdtJ7+YnKw/56GDQWMB
         NxhJFl+wi+Dbr0QND2bHE75l1vQs89zYgICCz4BxJljWfM15HvlKCdNFYJ/3S52agUXG
         gyEg==
X-Gm-Message-State: AOJu0Ywlq5P+WuF+KubMs8GdbWU9K9wIgKMwaztKa735ZaDYy+O3tUAg
	fMUSUEZayYASsG4AruV11Ns=
X-Google-Smtp-Source: AGHT+IHS2sidwtzlwMlNNfv5a2Y8kOdRzXeqsTqlzdqDMhnJCpenSQnDw0POV8nfpGsQV/DXrPv5FQ==
X-Received: by 2002:a2e:9bd2:0:b0:2cd:2332:d4a1 with SMTP id w18-20020a2e9bd2000000b002cd2332d4a1mr4468145ljj.25.1705519111081;
        Wed, 17 Jan 2024 11:18:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:300a:0:b0:2cd:613a:8cc3 with SMTP id w10-20020a2e300a000000b002cd613a8cc3ls864054ljw.0.-pod-prod-04-eu;
 Wed, 17 Jan 2024 11:18:29 -0800 (PST)
X-Received: by 2002:a2e:8007:0:b0:2cd:63e4:75ff with SMTP id j7-20020a2e8007000000b002cd63e475ffmr4639852ljg.35.1705519108794;
        Wed, 17 Jan 2024 11:18:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705519108; cv=none;
        d=google.com; s=arc-20160816;
        b=hYKGu9y206Wf11afY8cW1w+qWZ2mtvy0iz6Vz5xajYEjpWZUgkWECT4N/2jJEJaZ34
         9fx7aHjiciSLc55+musNLFVPMR7criIYLjXXqKuF9FoK/zojs/z/892EdoTyZ8IOZ0bG
         r4hXwX5z+O0m7gOXifxX6bGuXTQe5uU+NltEyUKkoOWRlY8BL34gMzVaRGM0dPEm22eY
         +17ODu4x4vAFT2Iy2ZonvieE3mgOJppaUoEIe06o4Ic197GW/U54bbihygb5FpnCrmPq
         TGK03LAqtF3qpY6wMc+KTi1pf6aZB+1urXLI9wobHINdFtwQj8EB8Leh3snUiCwmZdvU
         G8Sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=RY9ElmoBN1yaIqWHYG7QtdZi3QcPx+E4bgcakiLYwTI=;
        fh=SaMKD/qpL3nGMJUrmiYLa5wMkbVnPqsoNrm4W3W8Cyc=;
        b=RvHJ2KpFFANXXzqAgLg/rxf7aRBvqYv8LEbhb9m+djRn95PMR6F9nGq5OSpypqv7Ec
         Ia6uPzj/Pn9OJh+AjpXZAdh3cOpHEjOQNHD4axwlabfPc4AkGD0Smf9urOJIaZMu/UIC
         sbozVE+z+FeOWhpTVsgXga1ObF0GSOkwm1JNCUoq+YmNoYthFsdtadtP6183VwKhnrYr
         qzsITwN/y14RrHCvB7bzK5LIc3VjX3g+rwUBSzoIgYUrM5LBCmOzAFnF4HOUyFjVtow7
         Wku8OsbR6WoNx18E1Qmwg0OdnZmIsPVBvTXoQ+Px72GM3Anic7U4smS1JVl7Bg+das7y
         ewQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=K7nzuLcd;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id q26-20020a2e915a000000b002ccdcc1fd1csi514720ljg.6.2024.01.17.11.18.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Jan 2024 11:18:28 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id 5b1f17b1804b1-40e8cf57d63so6945515e9.1
        for <kasan-dev@googlegroups.com>; Wed, 17 Jan 2024 11:18:28 -0800 (PST)
X-Received: by 2002:a7b:ca59:0:b0:40e:76f6:9613 with SMTP id m25-20020a7bca59000000b0040e76f69613mr3246094wml.8.1705519107822;
        Wed, 17 Jan 2024 11:18:27 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:9c:201:e545:8ceb:c441:7541])
        by smtp.gmail.com with ESMTPSA id bi13-20020a05600c3d8d00b0040e8800fcf3sm3597189wmb.5.2024.01.17.11.18.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Jan 2024 11:18:27 -0800 (PST)
Date: Wed, 17 Jan 2024 20:18:21 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: quic_charante@quicinc.com, akpm@linux-foundation.org,
	aneesh.kumar@linux.ibm.com, dan.j.williams@intel.com,
	david@redhat.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	mgorman@techsingularity.net, osalvador@suse.de, vbabka@suse.cz,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Ilya Leoshkevich <iii@linux.ibm.com>,
	Nicholas Miehlbradt <nicholas@linux.ibm.com>, rcu@vger.kernel.org
Subject: Re: [PATCH] mm/sparsemem: fix race in accessing memory_section->usage
Message-ID: <Zagn_T44RU94dZa7@elver.google.com>
References: <1697202267-23600-1-git-send-email-quic_charante@quicinc.com>
 <20240115184430.2710652-1-glider@google.com>
 <CANpmjNMP802yN0i6puHHKX5E1PZ_6_h1x9nkGHCXZ4DVabxy7A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMP802yN0i6puHHKX5E1PZ_6_h1x9nkGHCXZ4DVabxy7A@mail.gmail.com>
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=K7nzuLcd;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Mon, Jan 15, 2024 at 09:34PM +0100, Marco Elver wrote:
> On Mon, 15 Jan 2024 at 19:44, Alexander Potapenko <glider@google.com> wrote:
> >
> > Cc: "Paul E. McKenney" <paulmck@kernel.org>
> > Cc: Marco Elver <elver@google.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: kasan-dev@googlegroups.com
> > Cc: Ilya Leoshkevich <iii@linux.ibm.com>
> > Cc: Nicholas Miehlbradt <nicholas@linux.ibm.com>
> >
> > Hi folks,
> >
> > (adding KMSAN reviewers and IBM people who are currently porting KMSAN to other
> > architectures, plus Paul for his opinion on refactoring RCU)
> >
> > this patch broke x86 KMSAN in a subtle way.
> >
> > For every memory access in the code instrumented by KMSAN we call
> > kmsan_get_metadata() to obtain the metadata for the memory being accessed. For
> > virtual memory the metadata pointers are stored in the corresponding `struct
> > page`, therefore we need to call virt_to_page() to get them.
> >
> > According to the comment in arch/x86/include/asm/page.h, virt_to_page(kaddr)
> > returns a valid pointer iff virt_addr_valid(kaddr) is true, so KMSAN needs to
> > call virt_addr_valid() as well.
> >
> > To avoid recursion, kmsan_get_metadata() must not call instrumented code,
> > therefore ./arch/x86/include/asm/kmsan.h forks parts of arch/x86/mm/physaddr.c
> > to check whether a virtual address is valid or not.
> >
> > But the introduction of rcu_read_lock() to pfn_valid() added instrumented RCU
> > API calls to virt_to_page_or_null(), which is called by kmsan_get_metadata(),
> > so there is an infinite recursion now. I do not think it is correct to stop that
> > recursion by doing kmsan_enter_runtime()/kmsan_exit_runtime() in
> > kmsan_get_metadata(): that would prevent instrumented functions called from
> > within the runtime from tracking the shadow values, which might introduce false
> > positives.
> >
> > I am currently looking into inlining __rcu_read_lock()/__rcu_read_unlock(), into
> > KMSAN code to prevent it from being instrumented, but that might require factoring
> > out parts of kernel/rcu/tree_plugin.h into a non-private header. Do you think this
> > is feasible?
> 
> __rcu_read_lock/unlock() is only outlined in PREEMPT_RCU. Not sure that helps.
> 
> Otherwise, there is rcu_read_lock_sched_notrace() which does the bare
> minimum and is static inline.
> 
> Does that help?

Hrm, rcu_read_unlock_sched_notrace() can still call
__preempt_schedule_notrace(), which is again instrumented by KMSAN.

This patch gets me a working kernel:

diff --git a/include/linux/mmzone.h b/include/linux/mmzone.h
index 4ed33b127821..2d62df462d88 100644
--- a/include/linux/mmzone.h
+++ b/include/linux/mmzone.h
@@ -2000,6 +2000,7 @@ static inline int pfn_valid(unsigned long pfn)
 {
 	struct mem_section *ms;
 	int ret;
+	unsigned long flags;
 
 	/*
 	 * Ensure the upper PAGE_SHIFT bits are clear in the
@@ -2013,9 +2014,9 @@ static inline int pfn_valid(unsigned long pfn)
 	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
 		return 0;
 	ms = __pfn_to_section(pfn);
-	rcu_read_lock();
+	local_irq_save(flags);
 	if (!valid_section(ms)) {
-		rcu_read_unlock();
+		local_irq_restore(flags);
 		return 0;
 	}
 	/*
@@ -2023,7 +2024,7 @@ static inline int pfn_valid(unsigned long pfn)
 	 * the entire section-sized span.
 	 */
 	ret = early_section(ms) || pfn_section_valid(ms, pfn);
-	rcu_read_unlock();
+	local_irq_restore(flags);
 
 	return ret;
 }

Disabling interrupts is a little heavy handed - it also assumes the
current RCU implementation. There is
preempt_enable_no_resched_notrace(), but that might be worse because it
breaks scheduling guarantees.

That being said, whatever we do here should be wrapped in some
rcu_read_lock/unlock_<newvariant>() helper.

Is there an existing helper we can use? If not, we need a variant that
can be used from extremely constrained contexts that can't even call
into the scheduler. And if we want pfn_valid() to switch to it, it also
should be fast.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zagn_T44RU94dZa7%40elver.google.com.
