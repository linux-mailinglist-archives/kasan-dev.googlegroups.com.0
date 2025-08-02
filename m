Return-Path: <kasan-dev+bncBCUJ7YGL3QFBB5EGXLCAMGQEYUU5SRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 322C4B1901E
	for <lists+kasan-dev@lfdr.de>; Sat,  2 Aug 2025 23:30:30 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6fab979413fsf56078996d6.2
        for <lists+kasan-dev@lfdr.de>; Sat, 02 Aug 2025 14:30:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754170229; cv=pass;
        d=google.com; s=arc-20240605;
        b=OQl/ImBwFEgjMNYJWbWkSa+dSVRqlIEHHuagxMhmGfggLAAADuMyP13TviRhZz1/n9
         AcrnvS2V2NRweYk99Q68UoSeAYUBBp5L0pRTuDYeJGItkq/lzbk7PrOLGTvoltR9BY7a
         23PNsxjvFj6z3yKZIE+vVLVlqp2QQWGR+NcqH/+2LoT/n2jhxLy80YyTGRv/CrGqgRLT
         PoRsPNJxVWQy/MUPceNe+JNXsfw80mH0pVNoTmKfOmW6tnvxx17WBbLK69wnrWtloW8P
         agvCx+d3AAlOZR2fmYJfj3vHZF+QDskRL3qEmwE3RR+2CASLLDKothMhqo4Kevfk2Fz/
         nEgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=egw19BoCtdhUE4gAd25k3iSGsHN+xNa7O6dJVKE3l2k=;
        fh=Q29/Gxe4QeVAw3fq2CQ8IXojrXjVng8eLJpCT3BTYUw=;
        b=C4HTuhnXSa3wXw1jfPRJFkK5853msR8V7NGPCh3nX/Pa7C74nmz6he5jU5UU1IcMC/
         t2SgpM6nNoK4DSYU7V8FcNHs4RNTvqiPou90mF9RW1RfYXF6e80iEFjaid2Zy6R4q86w
         pN3tNxlaTVRjc6ei+UcmHS0PzyRef7iGxzpm1oHnSEBYsik04JpOni9HcvnX4D2sY9Vv
         Uv4b4poXVFUw6yEOR7kxl0lw4/8veWfm7PzDs1Lx1lX69HBNeFy26SyO4kuDQ2iTeEW+
         96isg155K6kWG9ByuASblmeAlM4dHlhT5EHEXttxaZxCF3eZDFWWN5b83wRBcl2YhI7c
         AGtQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=VJJcui2K;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754170229; x=1754775029; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=egw19BoCtdhUE4gAd25k3iSGsHN+xNa7O6dJVKE3l2k=;
        b=dDpGSG51wldTlzMqAJGMpW94bcw92n4EOn37iySWUUyInqTpYDTaDxf7t+W7TK61KJ
         6NFqVDTxyByZyXpRi8WnJ9UUGMVva9NKHHUG+6oaR5hzrCxUlQqU8j2PSQVz6VqmrhqI
         0UuR/PRVdKJUkoPm5s/F7AWsHG3rwewWaIHrZWTO9vFOM5vv+DtLAB/l5SB5zV/dpMi4
         evcMPuzKHbcRlXz6xpmDOvhTyH8SWFj+vniKxjfUnJNuBotyKEVM0IzGiluNf3yRRY3N
         /BiRuRaII+Ux1WghaUJDigk8QIXzFh4+bTQ9yj11srzjaq9OL+i0PPBWC7NE7C6QBYhj
         eEeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754170229; x=1754775029;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=egw19BoCtdhUE4gAd25k3iSGsHN+xNa7O6dJVKE3l2k=;
        b=BJB8jeX8923br5orEQpfhhSYDcDLAEzOT0Cj9QXoaJy2xcXU1t+xYaB5TmPXucKvU9
         FakZ3VEe5lcpagy+nlxqx2NI57dy0K7yxkwgJRA2czzCYZkFQiQG8r8ZrwgVnd6uElPZ
         2IxGJQH32Mnzk8kOJRo8g8gkh1m/V4HA9mGO6ZG12w7LFD4cHJUDGhg0mc8ruwZc0OnL
         1auadZmbjFDOB4tKErLgVQCaPyFPfjWVfzRmdcuBfEAvQK2wzRfZuCQLoipqdBlRow+y
         4Yrv9fb6AAPqI+QP+YXJ5tmJZ5+N7vnVHnNcpj+Ivson8v3Lfu9C2NYCF37CXRSBcRWa
         z/bg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW/VAKUSYaRL6LoL5WlV8sATnu5m90At4gGLQvDO+c2bGL7/owZh98LxR7uq8dmVMoXBuJ/ZA==@lfdr.de
X-Gm-Message-State: AOJu0YzxijNVzfwpgIfkIv1AYDZKOVQEvhpCUBbwUe8xD0t8V1Kp1gzE
	kjld7zm9wpg3Yw/qOxh2qHKN9Y1el4j/VZXGAuFyBn2ddnMcJtjqfOVd
X-Google-Smtp-Source: AGHT+IE+By9TBJvRJ7HWaoUZ8xTpeZuSgTfCZzb6xtczkS29bQfJYkL6jtRrMfXPqow9Lw2P652ntw==
X-Received: by 2002:a05:6214:21ce:b0:707:44d4:2962 with SMTP id 6a1803df08f44-70935f3eab1mr77514746d6.7.1754170228773;
        Sat, 02 Aug 2025 14:30:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZekjUr5J3dXKBw5/gutOy0uzR7P3NcZgVFQseBjvMxFag==
Received: by 2002:a05:6214:2687:b0:707:1972:6f43 with SMTP id
 6a1803df08f44-70778b8b963ls48637696d6.2.-pod-prod-05-us; Sat, 02 Aug 2025
 14:30:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVfN6leBz2SBX9b+oadRd5uVcgJH9v8l4TvjQ0s2SApHEzJ5qOjy9OuKZpQq/rJ5xjewWSViHaKBgk=@googlegroups.com
X-Received: by 2002:a05:620a:a98:b0:7e6:7292:3286 with SMTP id af79cd13be357-7e69639a79emr570651285a.54.1754170227973;
        Sat, 02 Aug 2025 14:30:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754170227; cv=none;
        d=google.com; s=arc-20240605;
        b=GTsoCKIP2W+UT1NVmk8fe+Rua8Kvd7ywhfA3OKdwzkanO9TywjLEw0sdT/I86ib9Lf
         0F7HkkkQaEm8Y96M2ww7y1JzCoNVTo2aaPb8fuBriyn+OcIvrEhmqTj4si/PUlO8U6Tk
         OjyTyTcq6sYmDxW5/HkPt+P1WNJtFmp9b+jVwVwDLNlvgvzwlCn4Ovavz4W9dIo3DMF3
         lehD5WxqDr67lDWoTImYxs8rflmF3VgBP/1quTZCHRUA2ANEANvalTYNpuk4FPUlGoBz
         Rs6H0HPhb8OU4PPwQC9t5K+C62L6ZBpPUqwjnYMuf4eL1iAGscPuK3R7aNs5g88Y/G7H
         IhPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=QgTIJj96JrYlDKrKobagoiLVP2LCIkCXtdKE+c1ybNk=;
        fh=G+oqlCXTz7T7JTbY2RSs3jKYo30EskjOoE2wJNNupM4=;
        b=RWu8muwyEVTMJ3jpCRF8OLJPHCf1STv3/ZVJxlRg1o2EJllbZdC0uedxf+uWL0Ev4k
         yEpzfp0Y+ohg9XdMKxQIQFhixjtUMiugVO75uAXYFS3pgW4O/ZnO4ArEYYnovV4jTLIc
         gBIElluT171A/syzDJKK6hJtAYYTTWGOlObXeeAEnbXpmoh8H5Ag6bpK/koMUFZO6MnZ
         ICR6pmEkZsJ+h8kEtF+wS31Fr5GfPk776Sr/W89zNjTpHB3hBVBTRil3fA+p6Q3omzA3
         1L3vgwLUlMM4krfEajQjYDolSR6def3r1J2AXrlSMjPGguDwOqU1KK3EIiKkjq75cq38
         wq4A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=VJJcui2K;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e67f532470si30032085a.7.2025.08.02.14.30.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 02 Aug 2025 14:30:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id AB529A55136;
	Sat,  2 Aug 2025 21:30:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C8A7EC4CEEF;
	Sat,  2 Aug 2025 21:30:26 +0000 (UTC)
Date: Sat, 2 Aug 2025 22:30:23 +0100
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Yunseong Kim <ysk@kzalloc.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Byungchul Park <byungchul@sk.com>, max.byungchul.park@gmail.com,
	"ppbuk5246 @ gmail . com" <ppbuk5246@gmail.com>,
	linux-kernel@vger.kernel.org,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Alan Stern <stern@rowland.harvard.edu>,
	Thomas Gleixner <tglx@linutronix.de>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	stable@vger.kernel.org, kasan-dev@googlegroups.com,
	syzkaller@googlegroups.com, linux-usb@vger.kernel.org,
	linux-rt-devel@lists.linux.dev
Subject: Re: [PATCH v2] kcov, usb: Fix invalid context sleep in softirq path
 on PREEMPT_RT
Message-ID: <2025080212-expediter-sinless-4d9c@gregkh>
References: <20250802142647.139186-3-ysk@kzalloc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250802142647.139186-3-ysk@kzalloc.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=VJJcui2K;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates
 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Sat, Aug 02, 2025 at 02:26:49PM +0000, Yunseong Kim wrote:
> The KCOV subsystem currently utilizes standard spinlock_t and local_lock_t
> for synchronization. In PREEMPT_RT configurations, these locks can be
> implemented via rtmutexes and may therefore sleep. This behavior is
> problematic as kcov locks are sometimes used in atomic contexts or protect
> data accessed during critical instrumentation paths where sleeping is not
> permissible.
> 
> Address these issues to make kcov PREEMPT_RT friendly:
> 
> 1. Convert kcov->lock and kcov_remote_lock from spinlock_t to
>    raw_spinlock_t. This ensures they remain true, non-sleeping
>    spinlocks even on PREEMPT_RT kernels.
> 
> 2. Refactor the KCOV_REMOTE_ENABLE path to move memory allocations
>    out of the critical section. All necessary struct kcov_remote
>    structures are now pre-allocated individually in kcov_ioctl()
>    using GFP_KERNEL (allowing sleep) before acquiring the raw
>    spinlocks.
> 
> 3. Modify the ioctl handling logic to utilize these pre-allocated
>    structures within the critical section. kcov_remote_add() is
>    modified to accept a pre-allocated structure instead of allocating
>    one internally.
> 
> 4. Remove the local_lock_t protection for kcov_percpu_data in
>    kcov_remote_start/stop(). Since local_lock_t can also sleep under
>    RT, and the required protection is against local interrupts when
>    accessing per-CPU data, it is replaced with explicit
>    local_irq_save/restore().

why isn't this 4 different patches?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2025080212-expediter-sinless-4d9c%40gregkh.
