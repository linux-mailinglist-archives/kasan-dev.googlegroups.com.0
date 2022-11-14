Return-Path: <kasan-dev+bncBDBK55H2UQKRBHX2ZGNQMGQEQRZWO6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B41E62873F
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 18:38:39 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id be20-20020a056512251400b004aa9aadf60csf3500959lfb.20
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 09:38:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668447518; cv=pass;
        d=google.com; s=arc-20160816;
        b=s9O+G2Mg1urz4yG2mSyxfNfGkaNnPOzfyPti5xY7VCfOxx4P6SBvy3/yZju031N4k2
         42Y1MiaulMCOJNdePSyRB7ms6DuGVO/vWmz09LLlX23OpmaInwCc7Dvdvf510MoKdsVy
         jpoZPcpemyVy7GhancYTGg8Dx2TV7x2Zb07dxSboRaV0X9XSk/O0VbhYjXwqcpuEbuq+
         X+uduoAp1oDg17C+cWTmtpLvrYPbkyrRx20RFg9xG4Ptjldy2hpkkLiCv6aXe8rFKsjM
         vczRf7N2U/I/coY/gweNcPTpmmlMYz2WsioxoYFGuPMlylVdWuMt6ZlNKqJ8qI/hcJK9
         CVcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=KBV7d3l2o8jxULA81K8NIINGhuO2lwtPhh44pzw5q1M=;
        b=k0X5lAWxEwH7nAMpVRN5zVZl2l6zQHjdeO5WncvL23sRaOs8zGyfMIqMad2kklIcy+
         GrDri7Y2sygHtU82A5ViP+wwCNpM8RV5WO3wd5F/kCgQjUwSB8x2p7nRsZcTfnWA68F/
         Pvtp+QczaP264z2G0pWieuYBgnfIoV2iy0g2X75iAvN4H2GoAq3sd1UfQoKJAcNiphue
         JSfepGRu3dDMgWXfwaAdMyQSduphdLDVHVoN5fZFq6B/FD6ZOZ5Pl0bjl210+H16l+s0
         Eqy5NzOan9S+ma9hplo+tALEX5N4XyfbEnYo1u9GbqPXgBzCDS8UCDTvGC/FQ6fLcHje
         Sung==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="miXVHeb/";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KBV7d3l2o8jxULA81K8NIINGhuO2lwtPhh44pzw5q1M=;
        b=ibjRGhS8R1rV9s0npaZOuiWltU0azpWRZyZLYug0tcDijgeaFxvS699FxHbOQ7u8pk
         ZwcKwmEhP3rC2tBWn8iTiXDHwtn9i2UOAXlDNqHyUsjAJcjiKLb4wXRPDd7U8Z+rd+zb
         Sg+0zInpdVfkQ8Oolbn98jIWe6zT3iJgDpT8lh7KCNF4TxSfgLugXjB8EFvp1wex7Sms
         sSxOGa2SrtmUhtmZuy14Xz4D4niYZFvWTYQu2Sco+Sh/CGsoaRQWp2ETWxK/rTf9q7ZZ
         MNQfPZULEDooWfiYNzJmg9UFCK3kL98+02JVaV4HnxuM7hdgvzRZCdHxQqokc3/gz4kJ
         /E4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KBV7d3l2o8jxULA81K8NIINGhuO2lwtPhh44pzw5q1M=;
        b=ZXmnBmwAhSKRx1oUilDrrYPLfDvWPzh8XHSoViCNC6dSFPnbfVvNKPbV8hNXrOPUyB
         VuI3a0H9I7ltjIlACZLZHIdysMeo9oxJ4zHjRWwCdDtddbMHDV5Ci0OlDyXRJHmH37zT
         6904wzTn85zMK2I+B2ZJjaR7bEmqhmkltdjXPlKWkgqWE0NHJATc3l5UMT5aaikpMzrK
         QjvizN1BBiQNL8m2cNu70gL832fR1Mgeq75atL+WZqd46sqDEsd+hM2hgywkHJVDlbGz
         mlDFgedValYaDgOAS4TcHrOfrx/C8cyVLV+EES4sk33lj1CcU8EC5HrVsUgpAUU+6Gmv
         EXIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pkSyprOHErMNOVZ6fLRi1tIuzdzvDioMDfOrYnD3ivok86WwjS4
	h2qH6SBVslkkkaE6oos1N5s=
X-Google-Smtp-Source: AA0mqf4gfC+vOGFKKTrSvVXWweV0jYG5FHv1wfEaFKrCAPzyNfL1K1bFj+d6QYJGYDhkgvOlUVHa2A==
X-Received: by 2002:a05:651c:2114:b0:270:74fd:8fb with SMTP id a20-20020a05651c211400b0027074fd08fbmr4449682ljq.500.1668447518471;
        Mon, 14 Nov 2022 09:38:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:5d5:b0:48b:2227:7787 with SMTP id
 o21-20020a05651205d500b0048b22277787ls1262064lfo.3.-pod-prod-gmail; Mon, 14
 Nov 2022 09:38:35 -0800 (PST)
X-Received: by 2002:ac2:5e77:0:b0:4b1:7c15:e922 with SMTP id a23-20020ac25e77000000b004b17c15e922mr5292372lfr.214.1668447515522;
        Mon, 14 Nov 2022 09:38:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668447515; cv=none;
        d=google.com; s=arc-20160816;
        b=x7e7rpZlIqsVYnMFYNeyDcW/XL68opWCbxnFLoJpupGTm2iFKzLQbkNrH9hAApU7xO
         YbahWwlXRvEdrzNDfJOaeG527ToHLk81EtM9mDvpSTtc5qT0QMkCtMGwgloMVY0u0j+7
         AWqc5asr2HlKkkMDnuNejt/6nCBj+qyTzj7jTXO+1lcSRdsARuvmhk9RZBO4UM42gxdB
         M7t2O+lMKWU8oPM0Kw544j4hPFaLfvxgFHgTyPUSEQMZPD/Eg9exTOXEFxZ9PxN9HUn7
         kneAKitkGSkDGEPqgqg9QaJoFduitR5QHsVFxScOVfYI8ou0qFTUAxo947ZXo4OfSML9
         bJdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8PlpYY+vP5Rrdd5T8dnq/iP+uWZYn4QdrChaBtGnOwA=;
        b=mN3Olqe8PKQowvoHfPpa7AnErn6ZkrYKhhtsSndJ6WyLXUKAkBR9iDybCPOR5oCjlz
         K7HI2tBWgJruSXAwsdvSxAp7VnQ64t8MqPFDD/IVYRegRW4tIqlnyV/6C63tadPFHrgr
         jTvcFjGkEK0XgB4J8pvLQsM1W/Co6cve9oVeJ1v4rIc/5xbnDwvpwhtlD5b+CI+d+hGz
         7yT+i9h3uZ1ywTxRC+foHIVEFDg1I4bD1xRnab5DxJRF0fOasG7EReYh5tka9roXwGfm
         cNvbwECpwR9RlwGBKxIX1pSOKZg86+2NsKOy/Nk4qtKLG0prb5cQAvyDe9G1odOzkDNt
         vxQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="miXVHeb/";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id n8-20020a05651203e800b004a608a3d90asi349612lfq.6.2022.11.14.09.38.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Nov 2022 09:38:35 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oudPe-000qQm-4l; Mon, 14 Nov 2022 17:38:26 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 3C67A3010E0;
	Mon, 14 Nov 2022 16:12:31 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 213952C0713BB; Mon, 14 Nov 2022 16:12:31 +0100 (CET)
Date: Mon, 14 Nov 2022 16:12:31 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Sean Christopherson <seanjc@google.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Andy Lutomirski <luto@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	syzbot+ffb4f000dc2872c93f62@syzkaller.appspotmail.com,
	syzbot+8cdd16fd5a6c0565e227@syzkaller.appspotmail.com
Subject: Re: [PATCH v2 5/5] x86/kasan: Populate shadow for shared chunk of
 the CPU entry area
Message-ID: <Y3Ja33LyShqjvmQZ@hirez.programming.kicks-ass.net>
References: <20221110203504.1985010-1-seanjc@google.com>
 <20221110203504.1985010-6-seanjc@google.com>
 <3b7a841d-bbbd-6018-556f-d2414a5f02b2@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3b7a841d-bbbd-6018-556f-d2414a5f02b2@gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b="miXVHeb/";
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Mon, Nov 14, 2022 at 05:44:00PM +0300, Andrey Ryabinin wrote:
> Going back kasan_populate_shadow() seems like safer and easier choice.
> The only disadvantage of it that we might waste 1 page, which is not
> much compared to the KASAN memory overhead.

So the below delta?

---
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -388,7 +388,7 @@ void __init kasan_init(void)
 	shadow_cea_end = kasan_mem_to_shadow_align_up(CPU_ENTRY_AREA_BASE +
 						      CPU_ENTRY_AREA_MAP_SIZE);
 
-	kasan_populate_early_shadow(
+	kasan_populate_shadow(
 		kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
 		kasan_mem_to_shadow((void *)VMALLOC_START));
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y3Ja33LyShqjvmQZ%40hirez.programming.kicks-ass.net.
