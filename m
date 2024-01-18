Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHUNUSWQMGQEW6CWQBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id C468F831818
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 12:08:16 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-5cf8287b3bdsf2562929a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 03:08:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705576095; cv=pass;
        d=google.com; s=arc-20160816;
        b=P7zKYtpT0poCoMfA2PvmBj98bNoyFDrs5hjXJZSez9XCj1L/gQYLRZS2tYrZaXQlXO
         No48eAt03I8jvbLBwqa1zKQnBw1iYCgbMiAoDMeHlv2az+BsGQ6LbDmjnmIwKnyKVr15
         VJrvwVgUfFrxiaS5AMnWZfCLCkvovpE2pIB1ElZo4H2g5uSfyue4b1vIIa25BHJlHLJq
         DoyYuYrhhthnOIzjuiu5QGl2l3+Ot8nKvNo+sU3/hDqNfERw6EdPzGr8PALgfuFdZL1/
         JKyxgrTYdxPWhss6S1wUuP3sdw1HBG1CgXZhT3mk8aZ6ya+gFLuhTMcSFEc8WgmjoNPT
         2Yfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=f+9XIoKrp2uZN9707EDkegdkfldpSpOsBLCn6+vUN0k=;
        fh=RaGrguQm3JlAt/eMY4kDgJK9TlEP9rqRFFn6H9cF4a4=;
        b=GB5qpMEcbpjd9Ms0dz8q1DARnXpinvtwuMxz/CWkb8d3c0DClYi6SHi5+PL8Gax3KL
         JNDOzKlM55vlZ1h4mKJK1jH4t9W//SSl1Kg880KEPZuh3FBpW6mahRXV7jWBtp/b6IIg
         KQl/QteD060kqS16JaUGssR2ZybowQW5KAAnfYfqnFKIajOiBsaWrlR6+ogsZDxxRRq7
         xynqg30csh/99A9P+Rf2CvVVu8cjPlOejB83/UDPx5nooYkW+CymFQV2XQzgXmcCs+di
         ydkwuFsY/g+QohR8MrnlpAVAOv4GWSSxH73PTiqMNFajHsrHBvQEOiOhu+EfjDFNcW+Z
         eRyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qzrjm0e8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705576095; x=1706180895; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=f+9XIoKrp2uZN9707EDkegdkfldpSpOsBLCn6+vUN0k=;
        b=pcSUJwowPhdj+1SY9LJK2JcOMGVpvPNdWgWZnUttqB5uqc9RbMUdNBP9tpI2lPWOO/
         7dAqZGu4HL6uzqQR9Kvq70g3j1JeTU+d8i193AUtpg81pGE3/q6IB9bnESYwb1a5r/JC
         YIzgegZQP7TGEBk9PjtjK4BI/NMW/W70kphISlmlQPS29NgRmzAllPfZEgLUn6N6+YoB
         I3Q9kOezfU8E2CfJPXMACsby8BBuL6vPfdh2PQOo+xYT1DbiympMRPZBP2M/tKgq8Xhe
         Sh+x6cJOmCdQAH0NGjkG5VzmY7ZQb/8PeY3ULzvWJN0eclb13zTQPupgIdrZgObfmTiX
         GJQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705576095; x=1706180895;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=f+9XIoKrp2uZN9707EDkegdkfldpSpOsBLCn6+vUN0k=;
        b=afyjxHTQArRTF6LkmzJB4YHUd9b1AQ+vBgFl7r3qIx3rYoxqitizj8kZmxxvJZ/zdj
         RC2tcLIYj8EaVIH4BycQE/NHtFoXFjYqz03tfBpdHcj1K2ExpXBqpfryMlhqK+M68wcT
         F+6fguD0kj+6R+jf+uxGJ+rFUyO+SGAyZpIzSwn0iA3q68FMqGudt171S4Ujrp3mxhiC
         p0HXcyipDtPcMQ+AvJgmpv1UixntlNNtVpwhIxMquFAnKMxEIVlZLXQ6fc2Tz+faQ4iG
         ilxQk2SsVwHDGgNAjbt+7mVCjow4I3ScRqMt3QLssh/jaQkATkXtt+lrnc/Aq7UguS7u
         +5Yg==
X-Gm-Message-State: AOJu0YwzhfLLHu3E2VR62BF4UFHDTNLZEIkjAb9rtvR3gtJZMzuZnNXL
	zrFDtOpsojzUP0q/k5m4hUDgSL6q1hkeRpdKXwa0eyC1N2rua89M
X-Google-Smtp-Source: AGHT+IExcOM4sLuBG1eE5QNRw3qjJyfjmm7t9zo8CHLCRj9J3PWxBrHhTX7JcjuZp+fE2X3Mznq7yg==
X-Received: by 2002:a05:6a21:a5a2:b0:19a:46ba:d5d with SMTP id gd34-20020a056a21a5a200b0019a46ba0d5dmr516556pzc.97.1705576094617;
        Thu, 18 Jan 2024 03:08:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:2887:b0:28d:4760:98ba with SMTP id
 qc7-20020a17090b288700b0028d476098bals768609pjb.2.-pod-prod-02-us; Thu, 18
 Jan 2024 03:08:13 -0800 (PST)
X-Received: by 2002:a17:90a:62c8:b0:28c:a9d0:33ff with SMTP id k8-20020a17090a62c800b0028ca9d033ffmr474804pjs.62.1705576093316;
        Thu, 18 Jan 2024 03:08:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705576093; cv=none;
        d=google.com; s=arc-20160816;
        b=Ko8S32Vmkk6XDWTp5PzIFZHHDCqzemx9G3p+MXEIuEeP0ArJfTUXK9Gt4MNq/WH9Bc
         qPhT7nCa6mXPfrsZmZeYBxh9S2UBAMgxRy94crkW4g42tT2gwujJN5j6ovlkXJ2/YScg
         N/R0Sr8051ZUeLFxI5R3hntyizGTAE5Vl9E5xadUiX1f7cilxa5m7nvHwYNYYBNWJJzD
         OP8v4L/XwgbluvJUBKMaxuW/YnijuH0jLXiJl5Pbe1CgkJcpiP7H5wrfOqf7jHXoxXgN
         ZHmc7B9kaPcOlvgT5UmhtgFqHwloP2sDbTZPD+g4gJh/Wx+0TB7fZsAaIjGvLajTilYH
         eA9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3fBRUIb2Xioj9IoQ1nhfd3l3Jn6qijKU/uajCdRr4Q4=;
        fh=RaGrguQm3JlAt/eMY4kDgJK9TlEP9rqRFFn6H9cF4a4=;
        b=R1w9I5wguScDTHnIFsvvP+EwMIodwXjhhcPrS/jjXhoFL9oR7M1sjwscJiV8b1ZFV+
         9ALJry+izWi9CMKqRDajM89r9f8rUTpeAgXZXCX2k5r4qDMV+7ElfHiugi3/UB6QXKN9
         f8LaT+5vm55DA2NRQvrucQS6oTY4RyLpfHecaLxlB4h6kPOi+9RnPIuWL2Gq7FuTXCSh
         X7AWCOJx9D++nY0oetpAvDomi+d080EuK76UK39IOJQXQoSJpWdr8dL+wKEV00mhlPPr
         bTt4DSGw6H/M5h3kgEOOzo7SL3iif16h9QIPfLNwT/uge9blOFVvzSyuJpovT1c8pC3p
         mG6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qzrjm0e8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa32.google.com (mail-vk1-xa32.google.com. [2607:f8b0:4864:20::a32])
        by gmr-mx.google.com with ESMTPS id c2-20020a17090abf0200b0028e84886a0asi80325pjs.2.2024.01.18.03.08.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Jan 2024 03:08:13 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a32 as permitted sender) client-ip=2607:f8b0:4864:20::a32;
Received: by mail-vk1-xa32.google.com with SMTP id 71dfb90a1353d-4b77948f7deso3477607e0c.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Jan 2024 03:08:13 -0800 (PST)
X-Received: by 2002:ac5:cd93:0:b0:4b6:ef57:a068 with SMTP id
 i19-20020ac5cd93000000b004b6ef57a068mr362816vka.32.1705576092216; Thu, 18 Jan
 2024 03:08:12 -0800 (PST)
MIME-Version: 1.0
References: <20240118110022.2538350-1-elver@google.com>
In-Reply-To: <20240118110022.2538350-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Jan 2024 12:07:34 +0100
Message-ID: <CANpmjNPx0j-x_SDu777gaV1oOFuPmHV3xFfru56UzBXHnZhYLg@mail.gmail.com>
Subject: Re: [PATCH] mm, kmsan: fix infinite recursion due to RCU critical section
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, syzbot+93a9e8a3dea8d6085e12@syzkaller.appspotmail.com, 
	Charan Teja Kalla <quic_charante@quicinc.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=qzrjm0e8;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a32 as
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

On Thu, 18 Jan 2024 at 12:00, Marco Elver <elver@google.com> wrote:
>
> Alexander Potapenko writes in [1]: "For every memory access in the code
> instrumented by KMSAN we call kmsan_get_metadata() to obtain the
> metadata for the memory being accessed. For virtual memory the metadata
> pointers are stored in the corresponding `struct page`, therefore we
> need to call virt_to_page() to get them.
>
> According to the comment in arch/x86/include/asm/page.h,
> virt_to_page(kaddr) returns a valid pointer iff virt_addr_valid(kaddr)
> is true, so KMSAN needs to call virt_addr_valid() as well.
>
> To avoid recursion, kmsan_get_metadata() must not call instrumented
> code, therefore ./arch/x86/include/asm/kmsan.h forks parts of
> arch/x86/mm/physaddr.c to check whether a virtual address is valid or
> not.
>
> But the introduction of rcu_read_lock() to pfn_valid() added
> instrumented RCU API calls to virt_to_page_or_null(), which is called by
> kmsan_get_metadata(), so there is an infinite recursion now.  I do not
> think it is correct to stop that recursion by doing
> kmsan_enter_runtime()/kmsan_exit_runtime() in kmsan_get_metadata(): that
> would prevent instrumented functions called from within the runtime from
> tracking the shadow values, which might introduce false positives."
>
> Fix the issue by switching pfn_valid() to the _sched() variant of
> rcu_read_lock/unlock(), which does not require calling into RCU. Given
> the critical section in pfn_valid() is very small, this is a reasonable
> trade-off (with preemptible RCU).
>
> KMSAN further needs to be careful to suppress calls into the scheduler,
> which would be another source of recursion. This can be done by wrapping
> the call to pfn_valid() into preempt_disable/enable_no_resched(). The
> downside is that this sacrifices breaking scheduling guarantees;
> however, a kernel compiled with KMSAN has already given up any
> performance guarantees due to being heavily instrumented.
>
> Note, KMSAN code already disables tracing via Makefile, and since
> mmzone.h is included, it is not necessary to use the notrace variant,
> which is generally preferred in all other cases.
>
> Link: https://lkml.kernel.org/r/20240115184430.2710652-1-glider@google.com [1]
> Reported-by: Alexander Potapenko <glider@google.com>
> Reported-by: syzbot+93a9e8a3dea8d6085e12@syzkaller.appspotmail.com
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Charan Teja Kalla <quic_charante@quicinc.com>

This might want a:

Fixes: 5ec8e8ea8b77 ("mm/sparsemem: fix race in accessing
memory_section->usage")

For reference which patch introduced the problem.

> ---
>  arch/x86/include/asm/kmsan.h | 17 ++++++++++++++++-
>  include/linux/mmzone.h       |  6 +++---
>  2 files changed, 19 insertions(+), 4 deletions(-)
>
> diff --git a/arch/x86/include/asm/kmsan.h b/arch/x86/include/asm/kmsan.h
> index 8fa6ac0e2d76..d91b37f5b4bb 100644
> --- a/arch/x86/include/asm/kmsan.h
> +++ b/arch/x86/include/asm/kmsan.h
> @@ -64,6 +64,7 @@ static inline bool kmsan_virt_addr_valid(void *addr)
>  {
>         unsigned long x = (unsigned long)addr;
>         unsigned long y = x - __START_KERNEL_map;
> +       bool ret;
>
>         /* use the carry flag to determine if x was < __START_KERNEL_map */
>         if (unlikely(x > y)) {
> @@ -79,7 +80,21 @@ static inline bool kmsan_virt_addr_valid(void *addr)
>                         return false;
>         }
>
> -       return pfn_valid(x >> PAGE_SHIFT);
> +       /*
> +        * pfn_valid() relies on RCU, and may call into the scheduler on exiting
> +        * the critical section. However, this would result in recursion with
> +        * KMSAN. Therefore, disable preemption here, and re-enable preemption
> +        * below while suppressing reschedules to avoid recursion.
> +        *
> +        * Note, this sacrifices occasionally breaking scheduling guarantees.
> +        * Although, a kernel compiled with KMSAN has already given up on any
> +        * performance guarantees due to being heavily instrumented.
> +        */
> +       preempt_disable();
> +       ret = pfn_valid(x >> PAGE_SHIFT);
> +       preempt_enable_no_resched();
> +
> +       return ret;
>  }
>
>  #endif /* !MODULE */
> diff --git a/include/linux/mmzone.h b/include/linux/mmzone.h
> index 4ed33b127821..a497f189d988 100644
> --- a/include/linux/mmzone.h
> +++ b/include/linux/mmzone.h
> @@ -2013,9 +2013,9 @@ static inline int pfn_valid(unsigned long pfn)
>         if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
>                 return 0;
>         ms = __pfn_to_section(pfn);
> -       rcu_read_lock();
> +       rcu_read_lock_sched();
>         if (!valid_section(ms)) {
> -               rcu_read_unlock();
> +               rcu_read_unlock_sched();
>                 return 0;
>         }
>         /*
> @@ -2023,7 +2023,7 @@ static inline int pfn_valid(unsigned long pfn)
>          * the entire section-sized span.
>          */
>         ret = early_section(ms) || pfn_section_valid(ms, pfn);
> -       rcu_read_unlock();
> +       rcu_read_unlock_sched();
>
>         return ret;
>  }
> --
> 2.43.0.381.gb435a96ce8-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPx0j-x_SDu777gaV1oOFuPmHV3xFfru56UzBXHnZhYLg%40mail.gmail.com.
