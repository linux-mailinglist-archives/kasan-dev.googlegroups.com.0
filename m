Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQ4QZ6CAMGQE3MWEY4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 847BD375284
	for <lists+kasan-dev@lfdr.de>; Thu,  6 May 2021 12:43:15 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id v2-20020a7bcb420000b0290146b609814dsf1211555wmj.0
        for <lists+kasan-dev@lfdr.de>; Thu, 06 May 2021 03:43:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620297795; cv=pass;
        d=google.com; s=arc-20160816;
        b=K5eTnoegEwb/S/6lszNjRAbB5MAnWL67HP00QDkUYkUagZbkG8bbeTv8YZrfK7jbDz
         FaH5vmGYRMIYswLBr3HaxzNAaJE8wwjmO9PwAuM5ms9Rhd0olYBprrVMCadHF8SAPSN2
         jUUtRSJLSZXFRrW14Aob4cCSnBZApBQIg+bQSziihE8GPPtjSC5nDOmEwn8yyleMMnmg
         /f6kqptfbaA10Dr2RcF57yaxfvL2qHbJxJ9LMW6PPUIKAopLUa1jktcjXML24o9ASjYp
         C8x3h+xWZPL3n1+f0KcLJ8JAmBawA/81fZQf4zUYGYC4cH79MEstrbTgnDbl/9Gzj10h
         7cXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ucTfTFUZ1JguPgwOiCMXiLSi3QEcHWUK+f6PYjap1lo=;
        b=MIK5eKbsYwJbbFSB9s+QAhjTkB+IDEoY3w6LXq1Gv0TRWjpWWkBhPAfG27YTLFfh+/
         FHcjjFmMxMKmIGq31jIE/OcoM9hbES4UWcCOeD+OdAjZb+uth2ajdUY4ceM7zDtAIxnw
         FFSjR33n6luYNf2+mANyC9pjyKHsBepUP/s2tU+mADP2j5Rbdk4wD6yJx6gzCwCwrOeA
         2K/qQZetQ3ItMaos8lmGO9uXcWPPvYdraZZqdIhrZufoFQnNB1rfrQuI8VSMLThwr2WX
         7/0i7G/qqwCtdir3zTXptpJZ+XJVe5IhjUbmrA9fMX0SPzFr06+DOwfhA2pl4NzqFP2a
         yXJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CJmSrhq7;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ucTfTFUZ1JguPgwOiCMXiLSi3QEcHWUK+f6PYjap1lo=;
        b=UUGg/7aAhfvNbE/uzVd/mY4FqZhsjlLwjtTHI5T8zxA4+U6dDfAp9MTvUDpxYGx25K
         O7yVTdd9SeJGIaVMbx0FyLRDDQ9JZ+vg0634FD++ZYhuqjb5+7xCZQpeeZWVDZgz/wZ5
         QfpnSiasolX7UtteX1aUedE5/HbxL19towxEkluojNLO7gEEURf5Uu3mkMt6Ogk4r9D2
         vhshPpuNd0yV/PuZhAOEJLmKPsE50wCyHHBigU6HPdE2sg0gxDYTIjvy0IeFVPf6bSg9
         np+9kGZrwZa+1Q1Prujydq5YzsK1pZsA1cU9HCpd4OpPYlp15NR29cfVH5iWRYj2ECyU
         FUlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ucTfTFUZ1JguPgwOiCMXiLSi3QEcHWUK+f6PYjap1lo=;
        b=eRijFdHb062D3VPrjo+3HlMHzoTQfmuvrHHdIQ/UO/CTNs2DQxgZOjWBq88Uua9BjS
         Cmk1/PE/EvBiRUJBbpeGJje3xeOvHgY9O/dqlpf+g3uNYtftI2KFyd0CpXwgggsiEWr9
         4zckEl2KO1yvvwmq4snLcwrSTXX3GV+tW1Smjm0qksPjPERUhqZNeFHgukCI4O9iNI7B
         RNR71AbM76r1epTrcwympF52Os+do54al/W/NKuVT4zG9Yel7s3L6/LtgrhQsOvqlZA2
         k79VxI1i1MxHfsjlo7ma87qysbqIA1PYnRaHOtV6roxMH5Q4+++HTvxeffYA0nqk3Yxz
         jX5g==
X-Gm-Message-State: AOAM533xEq9ET54eOdlqDW1h4Sba7KpEpC30XB6DdfyI/J2Rj2+L3LOP
	xJn4fjm2tRbd7eXx1lPcrag=
X-Google-Smtp-Source: ABdhPJwL8AP7Lc/ryNvujF39aQ8BlW5mO6eKQGgw1MsusEW+AT3964JSRRLSjPTdcNdjNsu9M8BdCA==
X-Received: by 2002:a5d:59a9:: with SMTP id p9mr4114487wrr.289.1620297795266;
        Thu, 06 May 2021 03:43:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:64c2:: with SMTP id y185ls4440538wmb.2.canary-gmail;
 Thu, 06 May 2021 03:43:14 -0700 (PDT)
X-Received: by 2002:a7b:ce14:: with SMTP id m20mr3186286wmc.179.1620297794303;
        Thu, 06 May 2021 03:43:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620297794; cv=none;
        d=google.com; s=arc-20160816;
        b=Eic513qbOTSwXWVatB0/6twM3WKqyjgdZaf9FWBvDekkGrML761QRTXMY/qGPICRIu
         u2ipDQcz8BBl/RDus8hAawXKcyK132w9ilfQ+AZwxsQ5MqaBFfIjK4ea51kaYG41om8k
         mK3g+dqujqULvzz0YEN19PGtFQum9r8oeib9sERAqZJ/KXShycy+IQIPL2vj+TRx8J+z
         ovJND3t9RP/jMPfPMQD2OEDbHuUjGBn8NTvVCCsr2rhO1cqb7sxRiTJYOUKBRP3TNikZ
         tyIayDkZwpyEsOdhqNC5oztSJ0vsSjfbZ2thlkw3+GPGB1scpqbrIk+MIvtWKOttQ/r/
         PhEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=IPAb1iGejVFT6zs+1sVzWtohMm9y7vdT/ZlQY8nTMls=;
        b=zwbGTrDsun6iXVEBe2D67oZEnaYBT2VTPcWyqHFoYXxGvLMuXhV5vfZPFbO7e6TuGR
         xMOD/3wbad7hM5VZPa9Z2mkwQ3DB2mtVeNb95x9hZ+B9AGeee5elRGqooTydNkKQqnGY
         TSGfjzQxEQuR+GEBA3m5jE5hronThzJ32dajTHxAjoDta7sIbyx83m4+pchBP0BJ637Z
         xfJz8RrvSWZDl8uWEoLldhdm3h6q5azJdelCr0coM3rMJQAGRqjyc6bqdvOiArdyHITa
         l63B7Q2rzaI8MUzzjmf+Ax4KFsDq10LEWXbdmFjj6Y4DQTeUslmQq6MWsXzMFv4sZ6uu
         nqgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CJmSrhq7;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id c4si76932wri.3.2021.05.06.03.43.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 May 2021 03:43:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id b11-20020a7bc24b0000b0290148da0694ffso5055465wmj.2
        for <kasan-dev@googlegroups.com>; Thu, 06 May 2021 03:43:14 -0700 (PDT)
X-Received: by 2002:a1c:55ca:: with SMTP id j193mr14228873wmb.58.1620297793837;
        Thu, 06 May 2021 03:43:13 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:56c7:a45c:aa57:32c4])
        by smtp.gmail.com with ESMTPSA id 3sm2757392wms.30.2021.05.06.03.43.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 May 2021 03:43:12 -0700 (PDT)
Date: Thu, 6 May 2021 12:43:07 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Geert Uytterhoeven <geert@linux-m68k.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>,
	"David S. Miller" <davem@davemloft.net>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Peter Collingbourne <pcc@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	sparclinux <sparclinux@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux API <linux-api@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v3 00/12] signal: sort out si_trapno and si_perf
Message-ID: <YJPIO7r2uLXsW9uK@elver.google.com>
References: <m15z031z0a.fsf@fess.ebiederm.org>
 <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
 <m1r1irpc5v.fsf@fess.ebiederm.org>
 <CANpmjNNfiSgntiOzgMc5Y41KVAV_3VexdXCMADekbQEqSP3vqQ@mail.gmail.com>
 <m1czuapjpx.fsf@fess.ebiederm.org>
 <CANpmjNNyifBNdpejc6ofT6+n6FtUw-Cap_z9Z9YCevd7Wf3JYQ@mail.gmail.com>
 <m14kfjh8et.fsf_-_@fess.ebiederm.org>
 <m1tuni8ano.fsf_-_@fess.ebiederm.org>
 <CAMuHMdUXh45iNmzrqqQc1kwD_OELHpujpst1BTMXDYTe7vKSCg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAMuHMdUXh45iNmzrqqQc1kwD_OELHpujpst1BTMXDYTe7vKSCg@mail.gmail.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CJmSrhq7;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::332 as
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

On Thu, May 06, 2021 at 09:00AM +0200, Geert Uytterhoeven wrote:
[...]
> No changes needed for other architectures?
> All m68k configs are broken with
> 
> arch/m68k/kernel/signal.c:626:35: error: 'siginfo_t' {aka 'struct
> siginfo'} has no member named 'si_perf'; did you mean 'si_errno'?
> 
> See e.g. http://kisskb.ellerman.id.au/kisskb/buildresult/14537820/
> 
> There are still a few more references left to si_perf:
> 
> $ git grep -n -w si_perf
> Next/merge.log:2902:Merging userns/for-next (4cf4e48fff05 signal: sort
> out si_trapno and si_perf)
> arch/m68k/kernel/signal.c:626:  BUILD_BUG_ON(offsetof(siginfo_t,
> si_perf) != 0x10);
> include/uapi/linux/perf_event.h:467:     * siginfo_t::si_perf, e.g. to
> permit user to identify the event.
> tools/testing/selftests/perf_events/sigtrap_threads.c:46:/* Unique
> value to check si_perf is correctly set from
> perf_event_attr::sig_data. */

I think we're missing the below in "signal: Deliver all of the siginfo
perf data in _perf".

Thanks,
-- Marco

------ >8 ------

diff --git a/arch/m68k/kernel/signal.c b/arch/m68k/kernel/signal.c
index a4b7ee1df211..8f215e79e70e 100644
--- a/arch/m68k/kernel/signal.c
+++ b/arch/m68k/kernel/signal.c
@@ -623,7 +623,8 @@ static inline void siginfo_build_tests(void)
 	BUILD_BUG_ON(offsetof(siginfo_t, si_pkey) != 0x12);
 
 	/* _sigfault._perf */
-	BUILD_BUG_ON(offsetof(siginfo_t, si_perf) != 0x10);
+	BUILD_BUG_ON(offsetof(siginfo_t, si_perf_data) != 0x10);
+	BUILD_BUG_ON(offsetof(siginfo_t, si_perf_type) != 0x14);
 
 	/* _sigpoll */
 	BUILD_BUG_ON(offsetof(siginfo_t, si_band)   != 0x0c);
diff --git a/include/uapi/linux/perf_event.h b/include/uapi/linux/perf_event.h
index bf8143505c49..f92880a15645 100644
--- a/include/uapi/linux/perf_event.h
+++ b/include/uapi/linux/perf_event.h
@@ -464,7 +464,7 @@ struct perf_event_attr {
 
 	/*
 	 * User provided data if sigtrap=1, passed back to user via
-	 * siginfo_t::si_perf, e.g. to permit user to identify the event.
+	 * siginfo_t::si_perf_data, e.g. to permit user to identify the event.
 	 */
 	__u64	sig_data;
 };
diff --git a/tools/testing/selftests/perf_events/sigtrap_threads.c b/tools/testing/selftests/perf_events/sigtrap_threads.c
index fde123066a8c..8e83cf91513a 100644
--- a/tools/testing/selftests/perf_events/sigtrap_threads.c
+++ b/tools/testing/selftests/perf_events/sigtrap_threads.c
@@ -43,7 +43,7 @@ static struct {
 	siginfo_t first_siginfo;	/* First observed siginfo_t. */
 } ctx;
 
-/* Unique value to check si_perf is correctly set from perf_event_attr::sig_data. */
+/* Unique value to check si_perf_data is correctly set from perf_event_attr::sig_data. */
 #define TEST_SIG_DATA(addr) (~(unsigned long)(addr))
 
 static struct perf_event_attr make_event_attr(bool enabled, volatile void *addr)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YJPIO7r2uLXsW9uK%40elver.google.com.
