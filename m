Return-Path: <kasan-dev+bncBCT4XGV33UIBBXNLV66QMGQE2YKQUBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id CF1FAA3191D
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2025 23:57:34 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3d14a3f812fsf83389225ab.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2025 14:57:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739314653; cv=pass;
        d=google.com; s=arc-20240605;
        b=hJ4wXCJpd29sln1OQfrMD8/MdhyZjJY/aHfq0zQcOEpmJ3Gp0j5lcEMabvZA43St+d
         Z2R7+70lWaFv0GZ63wlDFbdbsbuRYwP8u/0eaB4nnLetDP0YpooIUWyLtytdF3a44fUD
         wgKyjiNMMooH7YJpcJZqV14H3LhDuLX/ThPXkEWpdp41ia8M1ZmQeRuiF+7ty2MCviIH
         jViLi62CA/icNxZR6jBCE9CMx9DJISn/A0DjqekjS22ekzBgPLMeQ5bH7W5SQn15R/vZ
         HGsIr1hxm3+J0xCBPkwpMjBd0sg8aH0pHZ8xUQ1TM9gVVQ7BL2AQ2mU8fkJcdY1zYnSY
         QBBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=SnWh/WL7VlbxJu69H7GU7IdBaDwE1/mT1Oi8czMTsyQ=;
        fh=Zm5fQcQapF0NiT6U9vu324IXjRArM+4ur0QbPCdnS8I=;
        b=aiOjOJVChhgVHQajtLBPg66JAR+qP80Nhv1RuZLQ9hmD6UkuRUBw2iNy945aBUaMTv
         G2EY1PoguGKdd67syufxhqqWlNHCd8Gzk18wOofI634T9yEcdUSUwUwH+TJcuJB6lLya
         hcV+OAbkZZEItItpuKbs/BNArO1MUfdHEXG4keqWHuVgTfsj6DEm4r7zJwCZbiNeul69
         NqE715L8Xo8c0xyepjhygp7BrwiunmVP70mUr2xCbLyIwsMxEJLst+V/eFal9CEGwxGx
         z7wJDXWDznC/O/X01aUvBwM8ntc498CEgIQVNsNf4QnI1p3fIARE4XZqtsRZwTPv3lU1
         4w/Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=BPCIvq52;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739314653; x=1739919453; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SnWh/WL7VlbxJu69H7GU7IdBaDwE1/mT1Oi8czMTsyQ=;
        b=EMQOuSfe8jNcAH14bRuTS8vlw6RjsRiAsVSbNL3VozWSUjLNyqXz2J8PicfUypHCf/
         XhTyxy26NoFvrWSkjOXNbM69PPssUDEwFkZuiaKbPr/0p4fBohMG5XNWk7E7c+mynmSD
         7xSIv5o8ePopXA3MTKPE/qe7KO8DkvulcfD0a0X1CaoPIFcqMPQC9FUcv9/hm52HQEIR
         eXMLWC8wbD8vlb4VLDMWn8n6OugV5+KqdCNZxKbfmYzDvgtn+42DUX0l7x8D0DkyI7RD
         hKae3RbfoXQ6mgMqtsTYTqaLi+983ZovTheFwFP5SI61bsM5vtuZ5QmGRD5yng1w+Bi0
         waBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739314653; x=1739919453;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SnWh/WL7VlbxJu69H7GU7IdBaDwE1/mT1Oi8czMTsyQ=;
        b=MZ/5ZOLtGURB51Y5WViaNpi5mILyvTDkXevxsi9cMOBLUpv1jgu9Tu2BCM+Ldn81KC
         l9kZ8KoUxLEHOF9owPld4nUGcnVr2DXC8Hg7RxjstA9fGGLBEpSX/J3sqgpfz7f+71kj
         ELf9F9fSiqliTn6AbkZcuS2dH2Pe03tUcqisRpYiwzW/jfJ+NEhkHgfwFBxXM09yMFxs
         7r5BbJ9QcywCDJuQHszuN6c/GmWofNA8rCpkItjIJQ1LGBJnGkEMIaeLL1ZlSeVlokUz
         efGkmlDecnRUcZ4kccxpv4al0m+YkJa/Lihcm25wj7L73Am9oGXPHk4o2t0hzBpJ4Zxt
         Lpgg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVXfmcJAFixoFXAToqaDWP64lMLLbUCF7onmPyq4W8gTFcEhNCSaFDlVVYvC3Us4ktw96Nlrw==@lfdr.de
X-Gm-Message-State: AOJu0YzndOyHSZIUOD2PwYudtnxL5PUWISA1CoFxyS4Rtq6mJOdd+77y
	Gtdtl5vh6+8NoIcCEOBulWfqN5NzKhLIcHLn7ihLGQuRQf5T8qz7
X-Google-Smtp-Source: AGHT+IEXXNkv/zeOCRtqHLYp1DxZW/NBDKJPpoBvm9n8OHJOAPmWlW2ftSWRQ8SeAGpyq6KQTs7GFg==
X-Received: by 2002:a05:6e02:3092:b0:3cf:ceac:37e1 with SMTP id e9e14a558f8ab-3d17bfc01e0mr13531305ab.11.1739314653484;
        Tue, 11 Feb 2025 14:57:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:6a11:0:b0:3d0:23cf:8ca3 with SMTP id e9e14a558f8ab-3d16ed5a512ls6153735ab.1.-pod-prod-05-us;
 Tue, 11 Feb 2025 14:57:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUb0lboeio6RUaFrrKJDwlVUYENFsQbRRPvRczLFi2R8lwXY4SkwZ/J4r+qEHNJcnTBCC4zXtQL0FQ=@googlegroups.com
X-Received: by 2002:a05:6e02:1d03:b0:3cf:c8bf:3b87 with SMTP id e9e14a558f8ab-3d17bf4a86fmr11996495ab.1.1739314652701;
        Tue, 11 Feb 2025 14:57:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739314652; cv=none;
        d=google.com; s=arc-20240605;
        b=IFpmTTkgVb72Ha9XPFxtoFe05KGjMhTzKR5xllcBmtEuNGb0vIXVKgArtyBClenM3U
         ixwIF5NMd+kXtYLnVBiKnDeRw0Wfn91l7F0iDI7buIjwc6gpoib93XHBVJsK0FksBCTg
         b3j521jXJ24C9loK+4jVVJ+XzIjEbu7laW5dKf0KTIgqdYJltOMuUp9PF9sQ25H0nOhB
         PoU1hCehspzWDorS/0oMALt4l7lJWEhKUjIawzs9VmEqmvC/mRUvHi8hTnYQIg1jVbsB
         6eBjvyUw0f5mkABhPNAzYO1FMUFpswDxVsdZEghMfOwkf6X1j8UMIqux/cWKvgCEFU6z
         JyHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=+lshG8H+waYmC/ZSWvT0rShMUdHv7fTd5EOGqZgeO78=;
        fh=V+GSRNlei3f1lfaGLeWuGHDKo16HoRBZ3NT2xC1JO2E=;
        b=MrpYc//igUD0OUIdGh4fxm1WbIv+Wzcey7ek8MopzHUtAGzlYT5mUzhqHkAWqdxhJ7
         BH1mjpwkllHXK1aZinAbxrenRHAC2yB8pmndd/WpEqUmZvx5Mg8HKJAGqI5JkPsAA5uc
         nk/QL2C3C8Exvm+wx8xxE91Aq4LaSxC2pxlQ2Y8tFBhDnJEDKYk6jlyYiYvjwNuANT0B
         GMJ765v1eJ9yOii92Yw1is4UtUm52EoeZM5WpxP6vcqDdA+Per13+ilt682HhvDu52BD
         UPC5kufb24dpD1LaLmF1YFQ+XasBnRo9oaZty0D5WrMKYtyT7WEjKAkm9xVnqtQCxfaq
         CGyw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=BPCIvq52;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3d141f2a96dsi4856505ab.2.2025.02.11.14.57.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Feb 2025 14:57:32 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 77E2FA40DF4;
	Tue, 11 Feb 2025 22:55:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2C955C4CEDD;
	Tue, 11 Feb 2025 22:57:31 +0000 (UTC)
Date: Tue, 11 Feb 2025 14:57:30 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Waiman Long <longman@redhat.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
 <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Clark Williams
 <clrkwllms@kernel.org>, Steven Rostedt <rostedt@goodmis.org>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, Nico Pache
 <npache@redhat.com>
Subject: Re: [PATCH] kasan: Don't call find_vm_area() in RT kernel
Message-Id: <20250211145730.5ff45281943b5b044208372c@linux-foundation.org>
In-Reply-To: <20250211160750.1301353-1-longman@redhat.com>
References: <20250211160750.1301353-1-longman@redhat.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=BPCIvq52;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 147.75.193.91 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 11 Feb 2025 11:07:50 -0500 Waiman Long <longman@redhat.com> wrote:

> The following bug report appeared with a test run in a RT debug kernel.
> 
> [ 3359.353842] BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:48
> [ 3359.353848] in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 140605, name: kunit_try_catch
> [ 3359.353853] preempt_count: 1, expected: 0
>   :
> [ 3359.353933] Call trace:
>   :
> [ 3359.353955]  rt_spin_lock+0x70/0x140
> [ 3359.353959]  find_vmap_area+0x84/0x168
> [ 3359.353963]  find_vm_area+0x1c/0x50
> [ 3359.353966]  print_address_description.constprop.0+0x2a0/0x320
> [ 3359.353972]  print_report+0x108/0x1f8
> [ 3359.353976]  kasan_report+0x90/0xc8
> [ 3359.353980]  __asan_load1+0x60/0x70
> 
> The print_address_description() is run with a raw_spinlock_t acquired
> and interrupt disabled. The find_vm_area() function needs to acquire
> a spinlock_t which becomes a sleeping lock in the RT kernel. IOW,
> we can't call find_vm_area() in a RT kernel. Fix this bug report
> by skipping the find_vm_area() call in this case and just print out
> the address as is.
> 
> For !RT kernel, follow the example set in commit 0cce06ba859a
> ("debugobjects,locking: Annotate debug_object_fill_pool() wait type
> violation") and use DEFINE_WAIT_OVERRIDE_MAP() to avoid a spinlock_t
> inside raw_spinlock_t warning.
> 

Thanks.  I added it and shall await review from the KASAN developers.

I'm thinking we add

Fixes: c056a364e954 ("kasan: print virtual mapping info in reports")
Cc: <stable@vger.kernel.org>

but c056a364e954 is 3 years old and I don't think we care about -rt in
such old kernels.  Thoughts?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250211145730.5ff45281943b5b044208372c%40linux-foundation.org.
