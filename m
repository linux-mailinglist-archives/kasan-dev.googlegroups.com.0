Return-Path: <kasan-dev+bncBCCMH5WKTMGRB57XXCWQMGQEPZQFJRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 21DD3835EC7
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Jan 2024 10:57:14 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1d74821bf53sf2694375ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jan 2024 01:57:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705917432; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZRHCfxcuLiUhg71Q+0nL06sr2IMrF8opEHo55fMmeuP/gMCYeT8GHfGGKUSj1SYMYx
         9t+9kgB/B/Vg1cLR19jYoL0T5GcNdftMnUspk+wKWUm1KRb40O+d/D/b/PSSGaSA6t/B
         UrrmDqGUIg8WifLvCJ90FSXrv9i2GILYykSSEha+CKW3Pg+mqjXvN9CkpDsPIR9GR+t4
         pNeYjd6AoyLcBIIrNkduu2jkCcQfcYNn6gPGlt6WFALRujY5W84Brb64pTvDMQAu6h+K
         hdJXbwifdubQBfMJthY7DWI7zw2Stzmc/V6xrYDtDaw/e33uD91Ybi7rmGNJzCgNOnB5
         y+Aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/WAtZIY1YVOALwIfpC9l5KR8KaBi79j4DvR/tM3rWY0=;
        fh=4ht1lxqK40Qw5GSxPmQglK1PhOybLzyGqfB4g6rdP7c=;
        b=eb7xsw4DrfQ+CiKmf5JuOi2GRPPeGiRVRz1umittt1tIU/aR94A+s8z5K+hP0VsFjM
         nCVLUJ0N2BKYAetA/VEuNbK4BD18JYXZfMwUB5IBqDbHUgPtWZtb2BQ9MDS5eCQS0V8X
         XDQ0qGfBhroI2FkDEHAIVNdJ7Vbj6hcPfsMAd3BKHatjDqaK8eLVwBa7YrP1cnClVUwu
         2ruDXJKjLpqtVtaMlKN6Tn7RzDW8fSe+YPWztVnceAUtMbqKgxPP5QZLPz4kHt9pEd7f
         G0dflgfAbyo72NQCusTlyPg7jG14U79i5IvFodqXfN2NZBRNay41iYrHl0/j8biMfxhj
         xMAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rxO7KzKu;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705917432; x=1706522232; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/WAtZIY1YVOALwIfpC9l5KR8KaBi79j4DvR/tM3rWY0=;
        b=CwHlDIdCQ/ZAOLjtPYKD1xI4yghZWdrrVxTzUp93vDFWgjIuU1PkN/zc+39V3uaUZ9
         0OuWHcS53Qk4xmKQliY0TmhlF80aeq1tBezIMd0dl31JaEfMDBemPIKhjcsVtTdIpfgi
         HxnpHqZXty6yHdelLgAYWh1lfu4lcOLGVOSVnW65Fbcuik3mFa75yFcozxS/B2BNKon3
         aeRksoPQrObAKC9hdms692CVX/wYStUdz+6q2Jq2uL+iesJgjK7b5GQJpf2mUSmyXuFw
         X6REsxS42HZYveG/IvejMpzg+Hec618qFchvrHJvNk8buBxWuXzZp49am9IbR+kkldkf
         qYCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705917432; x=1706522232;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/WAtZIY1YVOALwIfpC9l5KR8KaBi79j4DvR/tM3rWY0=;
        b=n2+TfWYzraESFXNNK7MywS0y2ejVPgSl8Etb7VzhxJuLmZTNZB/urZVwuHP79TH1lX
         sniZ5X9kxFPW8hPlbF5P9+rgbtneGJ7QS5oAufb62Qla7FMzZTxlKSxUWN12Vte+LixC
         cbZ3kIG5tP5l/NspBuCd6pZmT58FAVIsb4wRqoZxKEZd4xA6SEMnh9NxnZQ2/3BKRYwD
         FFZZrtvhmg7OfGQXWt1qrhtZrOPc0MX/GhCUtlnM5rYPPMngoujpDDKBJQRKB8BBUXoq
         B4zxL+mFDQiFvNuo7lHLbvPqMGr8yPHdX/tzkqH8KpeDmcpJ5U13bHG4TJ39PzZ/kWCv
         DaOw==
X-Gm-Message-State: AOJu0Yx/VbyOXEPBWXS8EPn+mb/1jGWOV0zbF8xkX9tiflcXANcm0I0w
	ZkDenTxQ3aarJ2V6YAbOL7o=
X-Google-Smtp-Source: AGHT+IE+uClx5/UbDc58S4AoU+xR+Qh3EFrMcS0CzwTzvDDNrgHuwcRlcFOc3ceQYkLx8ivRPDFKog==
X-Received: by 2002:a17:902:e545:b0:1d5:4c73:3c83 with SMTP id n5-20020a170902e54500b001d54c733c83mr234997plf.24.1705917432153;
        Mon, 22 Jan 2024 01:57:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f310:b0:28c:e978:2417 with SMTP id
 ca16-20020a17090af31000b0028ce9782417ls2362475pjb.2.-pod-prod-08-us; Mon, 22
 Jan 2024 01:57:11 -0800 (PST)
X-Received: by 2002:a17:903:18d:b0:1d7:3533:9660 with SMTP id z13-20020a170903018d00b001d735339660mr4402784plg.17.1705917431108;
        Mon, 22 Jan 2024 01:57:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705917431; cv=none;
        d=google.com; s=arc-20160816;
        b=IoPWNBohIX9LvxuDTlTxucjzbZRTarvOA79XLapAblfd/zutqKoaEPt9EmqqY3FpDp
         qbbVUpp7xj6dTeoDah9hUnjTqOnUMXMUVa0uu9P29ivQqoDucYoowLtl3pwWH6euaAkf
         91G69jsBrDAe7JI5GEEJNJH2zBVG8GOdSjJOn697ldi5QdPauU2KCXRymZH8Yhq7rfKF
         ejKWsJPbQB8BspNXgChfR2tBzyQ2AgNaV6hBPgQZlTpNAmOUj7qYFGBB7N/Dhtn5bjvW
         02RfnRbAqfcRYIdWII/lMYSEU6fkVeb1jcvzpRn6Qe9RAIQbR4TifKst26V/DrjEZjBW
         BMfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2rKc/goBzVwdZogi61XdfYVie6DI5305ZMhUyeoLBnU=;
        fh=4ht1lxqK40Qw5GSxPmQglK1PhOybLzyGqfB4g6rdP7c=;
        b=eiPUmKsDIMbegPeqmxgxOpsQGgY4BTp9UQtVkUpaMz9cd+q++1QwVuwlh7lO8pC5Ko
         mkvKQfE3LWbOT3bBAyfdNcbooCaBcqg5Gh6EyuhpPh3uC3G8PHxCFsdlw0mreQuGsXwX
         CDZl1V7svhlqp2NyMSdWSp9JI/VBOVZEAM/bDMmTYRRUeIftjhZNbvmpFGOdQWJRxl7R
         I6rN/brprNdAdBwGmuS1S6+i7vYnWZoHvg9fh45FBHB7n9VTWmn6NReQm3eCmXiRloKd
         P/DoXUvb/QBHEC9uDU5MP/ajaHwpzVINmg0Aoomq3mpf7ZF3gFyIYgat59jhjhEcpDBG
         /UKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rxO7KzKu;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id kh6-20020a170903064600b001d758eefaadsi76808plb.11.2024.01.22.01.57.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Jan 2024 01:57:11 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id 6a1803df08f44-68192840641so12884476d6.1
        for <kasan-dev@googlegroups.com>; Mon, 22 Jan 2024 01:57:11 -0800 (PST)
X-Received: by 2002:a05:6214:20a2:b0:686:1e2:747e with SMTP id
 2-20020a05621420a200b0068601e2747emr2720892qvd.71.1705917430029; Mon, 22 Jan
 2024 01:57:10 -0800 (PST)
MIME-Version: 1.0
References: <20240118110022.2538350-1-elver@google.com>
In-Reply-To: <20240118110022.2538350-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 22 Jan 2024 10:56:31 +0100
Message-ID: <CAG_fn=Wdkv8-=X1j-Rh8u-zhRCW9oY1GQ-=C3n=9eic6Vyr=iQ@mail.gmail.com>
Subject: Re: [PATCH] mm, kmsan: fix infinite recursion due to RCU critical section
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, syzbot+93a9e8a3dea8d6085e12@syzkaller.appspotmail.com, 
	Charan Teja Kalla <quic_charante@quicinc.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=rxO7KzKu;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Jan 18, 2024 at 12:00=E2=80=AFPM Marco Elver <elver@google.com> wro=
te:
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
> Link: https://lkml.kernel.org/r/20240115184430.2710652-1-glider@google.co=
m [1]
> Reported-by: Alexander Potapenko <glider@google.com>
> Reported-by: syzbot+93a9e8a3dea8d6085e12@syzkaller.appspotmail.com
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Charan Teja Kalla <quic_charante@quicinc.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Tested-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWdkv8-%3DX1j-Rh8u-zhRCW9oY1GQ-%3DC3n%3D9eic6Vyr%3DiQ%40m=
ail.gmail.com.
