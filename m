Return-Path: <kasan-dev+bncBCKLNNXAXYFBB574VXBQMGQEDPZ7TZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id C558DAFADE3
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 09:59:52 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-3a4f8192e2csf1556694f8f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 00:59:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751875192; cv=pass;
        d=google.com; s=arc-20240605;
        b=CxEVkaTXbcEcG78MVle79k6WfT3FYtnPLMbNU2sd90J2q5jLjGyUlJ271qAYsAOMir
         A/9/R7+lZMDNekzsNcPFoQNbU/CikE6wTW7gFiiDDbemX9ejS1vxFXKp4szkVqJnyR1H
         n4SxbgYDDUNn/w1tCDugK8rYnHSujfrGqZAttKWfdkfKEITKLlqRyie3r+cCY5yutPGe
         6IJSEjnN6je5YkEFHlKLUlbTw/SmHvTw+kX1CiZwIQi8usRKdRerXlwtQcjXaYLQQ4S1
         NpduawwfTycRNcWGdipxl8gU6sF5xd7aaBe8CnAZChm/XFjEi82jRXpuHxwArG52tcQD
         agug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=s4P5cIax5aHQRABJy0NECfDl8noBgnc94f80NPG2ec8=;
        fh=UmxvMGVwXMA3hwM054dFKAA7wXkpaChSHWxxj9aZH7o=;
        b=jNBO/sG9r1MRP29QCDbQrLG5h3hUHb9RL4+cuoaN7IG0+fBw7ltGANCz3xTeMlUQjL
         aLl3x0W1Z30SWNgH87ZQaWPFi/pqerxybPUO/gqwO73zh17X+ZY40gqRqwM/BOIcf6qK
         ZY924tr6DR1pqNrFDuchCJaBU/sbEqUHJAV1nlqP8mF921DeT5BjW6uqiwOfftMamt89
         v3NHZThi+CreAvzHsU/9ixVBswk0EC8QEdt6qd0dyDUQXak4qerLvMhaSZpIAgJDRtfC
         TrRBzsTHNOxQuueqVkJ7zGp9x9qd/Vcsdv6giLnsc6W6TBq17GltEXEcoM6faHVoEI0+
         F9Ew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=gMcyUUNm;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751875192; x=1752479992; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=s4P5cIax5aHQRABJy0NECfDl8noBgnc94f80NPG2ec8=;
        b=n0s6dVZSAHbY7Llm7X3dlzJMxTWXdd9ZR1WmyM1qDvgkd7wgAem5bAOmwMLRkeEdm2
         bO8xCKpUlWwSqa1K5H80vmGxxk4n+CHpg8lrVwwmx9Go311hM3K/2/6yf9thKF69I6UB
         5f2/vFEQHUe1G9QVRMOCNaD3XiNXEGRXAuDawCBjb0LRb6itbHlAwsFBhbad4lOrpyge
         am/XvlIGULvxoEiSOWAXmPrO8gV/fjsh5l0LFy9Ck3DAbX7ezwlx0/5IJ62jSOZxQU1M
         fSQjklp5O1zFskkBK9ocEFSc69M/fSRhRwNooA6tac5lDElsp+uYGfMNCClX+ZTI756V
         Q3EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751875192; x=1752479992;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=s4P5cIax5aHQRABJy0NECfDl8noBgnc94f80NPG2ec8=;
        b=LTSiyy6vKkqbMRoKXV/orZt+r3cj97ELu+TIHOs/YAXElprhvdZuHaODp/vGD137fC
         2+JIeem+Vy52ysQN3K2Hcf/mMCTmZB9mF4Pc3c1dHjJF4Yuh8ZQwN03xh9NjqC+U4MyF
         Yjpf2fVCAeEPLNmDk7/nFUBMplQO+wf96CoqFDW5isR5vP35hyVpw/mrY+aQmQULptF6
         NwrEWxVtRDOiqKOq47wBajAtlg9roX1llyYjmEazSHMuGkglbgtAxuEUt7qtozbtaga5
         6qDa/orpyZUXuH9gR+XI0CsYFP4T9VXS6RmjdNIjkuMUvevY1zLt8vxaMQOFJOiqaeU4
         0DXA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVUczLVZhGvcM8ZkObRtQYk1QreEZq8zoj8LXX8R/Zgzgbd71iKcpG/P5fhZ/BJTvnP/3l9dA==@lfdr.de
X-Gm-Message-State: AOJu0YyPXZ9xy5vuQU3X8jKNlCWmnPCEgqCFopqA7WVmQ8FipdiazWaO
	jk5/SizWTJmxh4m1LFVAjqW+4+uxU8wMgVdD2+8+k4gwfLodBhcmry1u
X-Google-Smtp-Source: AGHT+IG8YH+PowU/BK/KBs/VXjeJdehgr12Ws9J3i1i17k/AMPh3hMam6wd19D9ndtwzf5n2tHeyZQ==
X-Received: by 2002:a05:6000:40e0:b0:3a5:26fd:d450 with SMTP id ffacd0b85a97d-3b49702e8bbmr7723090f8f.47.1751875191747;
        Mon, 07 Jul 2025 00:59:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeP9QKhDnNgW9pfvJIQmWQwgnju1gw0ZkE69BsMW9GWjw==
Received: by 2002:a05:600c:1f08:b0:43c:edda:8108 with SMTP id
 5b1f17b1804b1-454b5cf7be2ls12777765e9.1.-pod-prod-07-eu; Mon, 07 Jul 2025
 00:59:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWTIPgpgE7OwTRP3y9OLZsxQOp4AZ9yjESxNQa6UCjM3IQrKGN+G3txTL1H3d3cbbmWF2XX1361jgs=@googlegroups.com
X-Received: by 2002:a05:6000:64f:b0:3b4:9721:2b19 with SMTP id ffacd0b85a97d-3b497212e09mr8768310f8f.11.1751875188787;
        Mon, 07 Jul 2025 00:59:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751875188; cv=none;
        d=google.com; s=arc-20240605;
        b=ZMitfLcTGqQnPSNFmqeJH5yg9vIA9MaDzzTb+jHmn0be5wx+0Vf1GpeiCiQPNmpBfR
         858ahdt1LfVpfTtHMoBLf9sVHoydg/8zwH6huemmCzGfO1jtKUVIdGvY7Pf53sC5EzKn
         42FyGSjqI7eXcntP6eyql3ethQNObQ8VtzdPCFbvqhbW6URY3Uj0KdZdJe8ztnnVt9pY
         tsGDKE0ynue+yL3tn1H8avijEXH1rAsQClDXfc7ZU8hJn7qIBDo6rcHk2Jkj59onnT4G
         iyfUxHP7u8YqcYEePz2r0t3ROQOR03/yHmWJH/l37jx0UlO9Xw9bbj8jW8YBZhoqs3jS
         BkxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=2j2sSg0ZRy6nf1ETEjPyw/XMmKiPm3C8NPTr78onL3g=;
        fh=H3LYN6rBkUOUVj8IBa7HpIEwNhSYoD9dGima4O/Bwhk=;
        b=TzhdRjc7QYQ21sTIPFPr6xFycpf/u7dZK1N2AV5j8nv6uxh9c7566tLmZ12B1Kt29l
         F9SQfl6uqplzfAQy5vgTymMUzg8/Dw6E0vPfqaocq5p181m7YyYp3RBrb9hc+/NN/INo
         BOpJ74qZjw7eMvizLKo6V/Y26Lv2cNyNUA4eJaUkpgzPv7go7dtHPpZPGIwPRRhiX6XM
         vF2qZbapulqtl0OXIwQq+tYXYJGErC+gBl6UdrKH+fkRcEgqPMYDQC0xi/XBvktznY4I
         WQGNFWBH8pQrz8CJitWerq2fBqCNAkLUgggJuS4DsMANJOjPW9Qa4uYfpXehCCy0uanx
         vViQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=gMcyUUNm;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b47156a702si149749f8f.4.2025.07.07.00.59.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Jul 2025 00:59:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Date: Mon, 7 Jul 2025 09:59:46 +0200
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	kpm@linux-foundation.org, clrkwllms@kernel.org, rostedt@goodmis.org,
	byungchul@sk.com, max.byungchul.park@gmail.com,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
	nd@arm.com, Yunseong Kim <ysk@kzalloc.com>
Subject: Re: [PATCH] kasan: don't call find_vm_area() in in_interrupt() for
 possible deadlock
Message-ID: <20250707075946.2lAwc0OR@linutronix.de>
References: <20250701203545.216719-1-yeoreum.yun@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250701203545.216719-1-yeoreum.yun@arm.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=gMcyUUNm;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2025-07-01 21:35:45 [+0100], Yeoreum Yun wrote:
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 8357e1a33699..61c590e8005e 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -387,7 +387,7 @@ static inline struct vm_struct *kasan_find_vm_area(void *addr)
>  	static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLEEP);
>  	struct vm_struct *va;
> 
> -	if (IS_ENABLED(CONFIG_PREEMPT_RT))
> +	if (IS_ENABLED(CONFIG_PREEMPT_RT) || in_interrupt())

Could we stick to irq_count() ?

>  		return NULL;
> 
>  	/*

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250707075946.2lAwc0OR%40linutronix.de.
