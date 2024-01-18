Return-Path: <kasan-dev+bncBC7OBJGL2MHBBM7FUOWQMGQERYEU4GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E616831602
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 10:43:16 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-50e8b421301sf9112513e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 01:43:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705570995; cv=pass;
        d=google.com; s=arc-20160816;
        b=P9TiOpf2rDzMDfOgvSw41dMD15HJD8AC5SBea9pHjkugTD+k7HULAjIKuyPo0I3jvw
         8r1lqWdQE5+dQGfqg+Hhz2KVDXPZ3UGP0i01L0QS29c4J0ixuzTI9BSd/N8hCtILIRm8
         2A8bNxEJz6X1at0ejLJvEpYeHEJQP5ofu8Hb8zNA9aOZaatq+Ssk/ciFSi7v1HqmYLL/
         hr5/CU2MkQmD8WhobJ7lB5Uue0iRBviq+WjLP8dPBuFuf6cJ1+FgHs0Zz+sj41GJ84SS
         E98jBYjVweWBoyG7Ln0RWUUWnjTKu0BSEyA6JrxBbEGXWoLuvwRRlzVw1e6lzrLJhOCf
         ebLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=sHAZouSs2I24Immj5pLR24k9Ddxzlkuzlop7JjTSnX0=;
        fh=SaMKD/qpL3nGMJUrmiYLa5wMkbVnPqsoNrm4W3W8Cyc=;
        b=WQvXYTe0nj+43P577TTCN/wrGVMY3Q9IVVA4ZFH3fSSENQD6hZuGptHu971lPGq8kd
         okCRM0sto0iiJnaP2mLdU7QWvU9XHwiYkvVaam0fhWiIpA7vo1K0mhlgqZLewKGnJspS
         jiXGvGbUvqu/t+KTzcgATJB9m9hymm+PcXkFl0P0L+R3YrNrcggvJUuIi/fCNIRUeyxg
         aHR8yerEIekqmf00/CE6042Qob5S0Pb5n1mdiyMriInzvTsTs0fsjx9LzbapzKi22gxS
         VYWeUrOH8YlUPVXhL2cJFTYn7Wl8HD/WC1gILvxCFhqCDPAWNMenCfAkka6cPhbrhhdA
         DbuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KQ9x9Pfo;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705570995; x=1706175795; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=sHAZouSs2I24Immj5pLR24k9Ddxzlkuzlop7JjTSnX0=;
        b=faBZqkEEOq0RlYPImzG+EModtUX+c/VsUpgRWlhE7sOGwvNQsNaWumGRoNRd8yhqnk
         l+owwynvn9v/1Em+bp2qtyMW3vCMMWw1A8CdId5/bSkM1pX/zBVhj+gGckf+AB5+tJ9n
         XpYWiFbfr2+sPQZ0jkjGHnDnSxY5aGThAtqhi2vp9fEWg13JlkSw9YXEOJaX1PU6OOmh
         leCGKhNIv2zDT7ZDQC8wxYIjPSiIZhlZwKZWXfsTbYe4lG6Sy3kbX7jNX7F8i9hxqRXQ
         9fNGPYVK9xQfY6PEk+QymDNcnCh5AQLUwai7ONMWBa83Du37UECp7lH9BXxhSjgEq73q
         YwrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705570995; x=1706175795;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sHAZouSs2I24Immj5pLR24k9Ddxzlkuzlop7JjTSnX0=;
        b=jyKvurqQOhgZdiTbVRMT/bl8TOUHqNtW0CCWudYQoOPc9Cds/tT0ucBlyE4hb0JuYX
         2n4Ub6pTkGbUpNc/s6HuBkbvR1TAgJQVOPRKiWn4wOk1bFb9bCONswFL4y5Epoc/R+Lo
         ffSZCYmd2FF0vExW3h+Ip9jrGnB3Z5cyO2a+7HZVYShg+ZXls9Pin2IFgOgkW9o0Y7B5
         HiA4TNj0US43ccBIQtuD8t0RSDcYofLxaLZdB9mRQt+7ULz83vZIYGWkdpt5l/zpLGEJ
         ZyGXownEmBBmLQ9yAJFT1743D45qb9oMOofAPFNSM9a75tS4RY7AeHP2rNdMA+HIYH8A
         4Csw==
X-Gm-Message-State: AOJu0YwUhcXlSKkjQlmwvbfuXUmTdR5StCPB5SH8Eg0FruHiWD6PSh72
	7sOqrT/XUw8npZw62eaP+tdJQZicz6pJbGOQAImmDbIlQ8wmYgEp
X-Google-Smtp-Source: AGHT+IHkbhIPYey55DLBYgd3wmtVTyZ6QlXKgfv/TYGiA+Ml4X65Sj+4fHO3WvTlIiwPBZllAM+91w==
X-Received: by 2002:a19:ca14:0:b0:50e:7044:704b with SMTP id a20-20020a19ca14000000b0050e7044704bmr195726lfg.90.1705570995209;
        Thu, 18 Jan 2024 01:43:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f01:b0:50e:7b04:a7a2 with SMTP id
 y1-20020a0565123f0100b0050e7b04a7a2ls51374lfa.0.-pod-prod-02-eu; Thu, 18 Jan
 2024 01:43:13 -0800 (PST)
X-Received: by 2002:a19:770d:0:b0:50e:768e:4cab with SMTP id s13-20020a19770d000000b0050e768e4cabmr181796lfc.205.1705570993062;
        Thu, 18 Jan 2024 01:43:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705570993; cv=none;
        d=google.com; s=arc-20160816;
        b=IhwAyI5P20+yDLANkINhAXjhUzJkJKjuXV/uR01pr+rQl28q8yK02l4uMUZ2UATmQF
         +NxJWEiTSW/Jdu+oKVruhhngg91PgpbYp0Qhh4MlOePuOgzwzUIHLOgb9BVLF9MrrTRQ
         zCt4vi7Cn3+FJEX0+K4w2RRneKRva7fFLyV5OJG6z0rmYeWylR4ntbVtDzp2dAbBdt9h
         hwvT19K2xj9bd22Snas7s8kCsPZfKbVnuKljPD6nhqYryK8EkGdvLCyfjg1Vng9dM5tl
         /eVS1MthZjUPlkheixBA34rj+ZIEBQGonaC2D2BXk1UJveHF7pCgIBhr/xMaxDoClmup
         Cxjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=cuYpIw9soBWDz51Uc9U824cyLkAJt+cFBIInHg6YOR8=;
        fh=SaMKD/qpL3nGMJUrmiYLa5wMkbVnPqsoNrm4W3W8Cyc=;
        b=DlgVxBB+uVU/QvERgYf//mJtq51wthBXV3ei+sWcOJ5JXq8OTZVvYvBrD3ZgrRGIgv
         yW/SO0hE+6Dq+UUC0VbEXl4kMQ4A0c1R2R70xzAIcXBJ0eV7ObfT4+oLTZFgfavOBXu+
         OcmhAVHpBR9hp/rscgFYtSBjFxrBIaGnQ46ICNanKvt4NqCYYCOTeEx6EZxqUQqtb5qP
         GDhdU9ZqeqLUGWfSL7chmkRgPdPkEhv9pUxhVGqsloP7VkRcx4q7UZSSkpFiWJ+yw5pq
         exn6zS9yJ+75RVjeiWei8QMoxw6SkFWctkPMi5uAgYKL9cSVjA7YTbPzRbVabDV+G91U
         AWnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KQ9x9Pfo;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id k7-20020a0565123d8700b0050e7813f310si120846lfv.9.2024.01.18.01.43.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Jan 2024 01:43:13 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-337b583453bso2368120f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 18 Jan 2024 01:43:13 -0800 (PST)
X-Received: by 2002:a5d:508a:0:b0:337:bde6:63b3 with SMTP id a10-20020a5d508a000000b00337bde663b3mr205462wrt.31.1705570992147;
        Thu, 18 Jan 2024 01:43:12 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:9c:201:9d7e:25fb:9605:2bef])
        by smtp.gmail.com with ESMTPSA id q8-20020adff788000000b003367a51217csm3581808wrp.34.2024.01.18.01.43.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Jan 2024 01:43:11 -0800 (PST)
Date: Thu, 18 Jan 2024 10:43:06 +0100
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
Message-ID: <ZajyqgE3ZHYHSvZC@elver.google.com>
References: <1697202267-23600-1-git-send-email-quic_charante@quicinc.com>
 <20240115184430.2710652-1-glider@google.com>
 <CANpmjNMP802yN0i6puHHKX5E1PZ_6_h1x9nkGHCXZ4DVabxy7A@mail.gmail.com>
 <Zagn_T44RU94dZa7@elver.google.com>
 <CAG_fn=XcMBWLCZKNY+hiP9HxT9vr0bXDEaHmOcr9-jVro5yAxw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=XcMBWLCZKNY+hiP9HxT9vr0bXDEaHmOcr9-jVro5yAxw@mail.gmail.com>
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=KQ9x9Pfo;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as
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

On Thu, Jan 18, 2024 at 10:01AM +0100, Alexander Potapenko wrote:
> >
> > Hrm, rcu_read_unlock_sched_notrace() can still call
> > __preempt_schedule_notrace(), which is again instrumented by KMSAN.
> >
> > This patch gets me a working kernel:
> >
[...]
> > Disabling interrupts is a little heavy handed - it also assumes the
> > current RCU implementation. There is
> > preempt_enable_no_resched_notrace(), but that might be worse because it
> > breaks scheduling guarantees.
> >
> > That being said, whatever we do here should be wrapped in some
> > rcu_read_lock/unlock_<newvariant>() helper.
> 
> We could as well redefine rcu_read_lock/unlock in mm/kmsan/shadow.c
> (or the x86-specific KMSAN header, depending on whether people are
> seeing the problem on s390 and Power) with some header magic.
> But that's probably more fragile than adding a helper.
> 
> >
> > Is there an existing helper we can use? If not, we need a variant that
> > can be used from extremely constrained contexts that can't even call
> > into the scheduler. And if we want pfn_valid() to switch to it, it also
> > should be fast.

The below patch also gets me a working kernel. For pfn_valid(), using
rcu_read_lock_sched() should be reasonable, given its critical section
is very small and also enables it to be called from more constrained
contexts again (like KMSAN).

Within KMSAN we also have to suppress reschedules. This is again not
ideal, but since it's limited to KMSAN should be tolerable.

WDYT?

------ >8 ------

diff --git a/arch/x86/include/asm/kmsan.h b/arch/x86/include/asm/kmsan.h
index 8fa6ac0e2d76..bbb1ba102129 100644
--- a/arch/x86/include/asm/kmsan.h
+++ b/arch/x86/include/asm/kmsan.h
@@ -64,6 +64,7 @@ static inline bool kmsan_virt_addr_valid(void *addr)
 {
 	unsigned long x = (unsigned long)addr;
 	unsigned long y = x - __START_KERNEL_map;
+	bool ret;
 
 	/* use the carry flag to determine if x was < __START_KERNEL_map */
 	if (unlikely(x > y)) {
@@ -79,7 +80,21 @@ static inline bool kmsan_virt_addr_valid(void *addr)
 			return false;
 	}
 
-	return pfn_valid(x >> PAGE_SHIFT);
+	/*
+	 * pfn_valid() relies on RCU, and may call into the scheduler on exiting
+	 * the critical section. However, this would result in recursion with
+	 * KMSAN. Therefore, disable preemption here, and re-enable preemption
+	 * below while suppressing rescheduls to avoid recursion.
+	 *
+	 * Note, this sacrifices occasionally breaking scheduling guarantees.
+	 * Although, a kernel compiled with KMSAN has already given up on any
+	 * performance guarantees due to being heavily instrumented.
+	 */
+	preempt_disable();
+	ret = pfn_valid(x >> PAGE_SHIFT);
+	preempt_enable_no_resched();
+
+	return ret;
 }
 
 #endif /* !MODULE */
diff --git a/include/linux/mmzone.h b/include/linux/mmzone.h
index 4ed33b127821..a497f189d988 100644
--- a/include/linux/mmzone.h
+++ b/include/linux/mmzone.h
@@ -2013,9 +2013,9 @@ static inline int pfn_valid(unsigned long pfn)
 	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
 		return 0;
 	ms = __pfn_to_section(pfn);
-	rcu_read_lock();
+	rcu_read_lock_sched();
 	if (!valid_section(ms)) {
-		rcu_read_unlock();
+		rcu_read_unlock_sched();
 		return 0;
 	}
 	/*
@@ -2023,7 +2023,7 @@ static inline int pfn_valid(unsigned long pfn)
 	 * the entire section-sized span.
 	 */
 	ret = early_section(ms) || pfn_section_valid(ms, pfn);
-	rcu_read_unlock();
+	rcu_read_unlock_sched();
 
 	return ret;
 }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZajyqgE3ZHYHSvZC%40elver.google.com.
