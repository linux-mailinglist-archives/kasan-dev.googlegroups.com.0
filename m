Return-Path: <kasan-dev+bncBD53XBUFWQDBB57JR3DAMGQEAP6B2DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C0B6B54231
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 07:51:53 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id 46e09a7af769-746d08b881bsf1704887a34.3
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 22:51:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757656312; cv=pass;
        d=google.com; s=arc-20240605;
        b=dsF7kA3WQJai0EoBB+8Pg8nWjMYeSOBr+C/+1Fz/eOHWn7UZZ3n35TW/fIVQU7G5ix
         py5GmE7RPVn/qXl6BYap5/T/uoUXy4geDzq3sVlJQ5z2bVRun/GpzL7XO8hSFJQK5fSH
         FsCLKNdPyhm3SA/JusJnTOMmeah8YMbXS0ulq2n1N3ngOLurAt1xroDvvVoiIdRr54db
         8Daucwo6BpTjFZiYiWemyRjuJe+25D9sEKU6q1tWKd+wjg8u8wMxniyxXkGt8RbRCcg6
         hGpD8z7rrcYRnQKy8ajrUB1cyFpl5KplP+gL/b8kZl+L7QpmC8i/+YuBpyL8Q9tX8/qd
         DqOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=JQHGYW/umeFe1KvA0vQob1NmZRLLRdM3Tv5SR1Byvjo=;
        fh=0EgWLcDsydXSRNq8K35AmsHk2owLTLaVmXGp0gGVGYE=;
        b=Dcv82CUZQ6Ka7eOt1KLAVTzmgXRySzRudiB/NDDtANaHucLeV8QTclXm5b2YKxqNwu
         QUZIphILKUdBbzj+jmSJKfB3C777Nb4nD6VhDWMPdICyPBvUcDOhsfLry3oUcE65ctBp
         Iw124+50j5rl1sj2mul9LdP2iguvEjDoRkFMQDQCxZ8bDHEkfksn1486qI5KeCmahpb8
         bQ/pKTtCkGxbd58P9hjpKOWhYowHjxh74cHbAoybY2ektth2JaTRFmL/SOhXpt877MhS
         bz1epDS3ro1/5V92d8AhTsU3uI9aPR5LNkHWHB6kJeWSMw2JDw27ZY8GeluqbiMzhp+n
         4uyw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=L96ka5hP;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757656312; x=1758261112; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JQHGYW/umeFe1KvA0vQob1NmZRLLRdM3Tv5SR1Byvjo=;
        b=v9i/2VN8dYa4qt1gHam6j+nDPZEllW6p4wZjY4yy+XZvhvqsJ88vq9y460FU3U0vk4
         mmg1MC5vFsb8JaDnuMmnCOw/RUBJDEuBPoChihZvBP399F4Y05XWbB3v8RUdPKUT7Iqe
         D8mDItMq0buEc2VEjSq3VhJncYau4M3E/7bRfYgQYrsqvscwM05GoVLW10i6B4a5tIMI
         83P50t4ODxb3Lzzl8zbobmnN194BWIJbnA6dkq2y876ZVN8Hxe3Nf6YHjkZuPpuuSgiU
         haRZo57KC7TajpTp1VwDjvU2K/ZnyhbMTnU/7nTs7YablgjLpeN29rAhXSY59bZIOelS
         Zcxg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757656312; x=1758261112; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=JQHGYW/umeFe1KvA0vQob1NmZRLLRdM3Tv5SR1Byvjo=;
        b=MJ68c0b78KAjAduA2S2vqhCcfyya9t41XVlRIal6IMPbQTVYr5pGuRadaGx83/TY2N
         S8huO535BTyVU5r0qV58AOyexblVbw8TYi9/c0WTTMVmJx1l2ZJdPQ949JJBVG6yxen5
         epuAIz35amrMTA9ePTYWgMBOiVWqVswMhd+OUy/KXnOp0QGa2Yt2DLlcQb1z2B0J4Uzv
         q1gcv5llbafVE0dOHG03qhZsPC6aoFFivm9+PfgyS73WO61GX9RXng4uUucoCegrxGlK
         rEsiaoNbhqr2iDHnhP1FqUTJCRhNOKYAzm7V/gDVmjE2dDHhjlVB4lFKlLL/oggav/rF
         5IFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757656312; x=1758261112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JQHGYW/umeFe1KvA0vQob1NmZRLLRdM3Tv5SR1Byvjo=;
        b=by9w8iAxH5TGVKLqvEpBHfUZX9sRCW3NGYeftdFBDPsC4XmhfCrYfSN74GaTRx3rOt
         74co1mivfrLV1X5eqbxqjjyOVFqzp+J8EMY0O/b2+axy8lJM1m/pocKHjTURi95QoA1A
         oDiJJB59xFkRLcz2r6Li7grS44cmhf22SdCBj2ar/cMWPancU9dVWqTN+ZDRI6EGhocm
         QP9YJKlXUKwn40pqZpw5Fid6jFiKx4x993hv2Fespt/uTZfGHGb3OdVtNLFdfnKvLWlj
         wggg3K5ts+hJ7Ra2Yqpcinyi1RLSDm+y8EWueMw9K9LJRa++UeFGv/zeOatZKqcM/bQp
         hxUg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVEAY0RDhrhHXD7SCwz6WbI1Hvc6exMnd9luOhTmAbFR6mPlmqpyWMnlCKiT6OzdSo4dezHmw==@lfdr.de
X-Gm-Message-State: AOJu0YxB+B+qSV4xFj7j2lp3wFlyHpDjPPHIxYr4P/iIJrCNa2kksp9I
	aBupJ2g+x4wz/GmQ4CHyy/vgmTySpdbVXGHqBJb6pAM361QILRvJpo4v
X-Google-Smtp-Source: AGHT+IHB9GC5sfc+L04RFrxvwzm3inOB5EwC9AFRTzXMpTFh3lSl9wkvUZ0U3x4+zE6s0e6qbpEoxw==
X-Received: by 2002:a05:6830:498b:b0:748:317:dd82 with SMTP id 46e09a7af769-75354b0b560mr993579a34.18.1757656311722;
        Thu, 11 Sep 2025 22:51:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfeLlPZdMq9JxjEAVharW/9VlAFw/LMRmTzLojI2CyRGw==
Received: by 2002:a05:6820:510d:b0:621:ae05:f5a0 with SMTP id
 006d021491bc7-621b44ea992ls235686eaf.2.-pod-prod-09-us; Thu, 11 Sep 2025
 22:51:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWA9JeYXOpjY0MSE02ZamcQrWlIFYeN9vAJI9AbJZH15xIrMLDtYAtVd8Sp25xpduEWVo5evLJ5VbM=@googlegroups.com
X-Received: by 2002:a05:6820:509:b0:621:69bf:7629 with SMTP id 006d021491bc7-621bedb2793mr944782eaf.8.1757656310342;
        Thu, 11 Sep 2025 22:51:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757656310; cv=none;
        d=google.com; s=arc-20240605;
        b=edR09BxxEshcJq1w1tALKSxsW9CnHynrB2euUr6wAjdZJ4CIK61gZgj0KSgX3ywSlS
         XKrgLugNbqLz7DyzQrYeXJVFAsjtzjVg3dd3fH9ZL5SGMRCGc0hbSMsyIjUPaclnwGGI
         WtlMjouZ1B9pEoiyQSyZ9SxXpY2Qq3HhVZC16j3jcOVbkl2fR80fODlsWJQonLvGBpFF
         95o3rorOuwWSdhSxNpIZDiIbdKiZfajKzVqDQY+k6I1zER3iCeMeKDwyzrqiW5cqlKIO
         iVpQMf4WklTmJYZCTip4qWJR1h1pdola4zk3VxtH1a52rC5tOSb9PERgu0cNF5+0wYYR
         HE3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Wwxrf7orhL2KYO0iCZZdsGPUWyavjuMuxgjcqzj0tsA=;
        fh=QSNTk2a6xYlcjd+lLJEym05UFHM8DoOMwd3ddN4m0/o=;
        b=CPeh3d7P/QyqAAGopJvGBIqfWksS89Ftvgd8riUtwqo4bOi8OQLuD7jLuz80CNqHql
         mydgcYyw1dcTUho/xR7H4ZhQEh5OARgC2zhCuu/bc8YAMDpuzIBw/mf4lUyAWI0mzQx/
         UihUFiRWOiZnJaOdgUwsZCpAnHnsC0HCnl1mH8G4HPhOpqSIe4QF6M45r1zgieJRW7mY
         ww4S9nXaOfrRwGoX5dFFgWatcy42h6ze6GhRxnhJMnPK8ubRoDGpRiez7Zpbwsgx9Jjd
         CBxTJv3wffBjbsuTOqnOS0h5GMsCTDOM8lx/CYZbyOD7j4cCjrb5oC/bdNR75Wc6foxz
         7z/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=L96ka5hP;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-621bf9e4028si37651eaf.0.2025.09.11.22.51.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Sep 2025 22:51:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id d2e1a72fcca58-7728815e639so1205094b3a.1
        for <kasan-dev@googlegroups.com>; Thu, 11 Sep 2025 22:51:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVRcJWRLGh0qxOI/cNxPf7EXyO5++ASbhyK1UyU0drlC6Fy8S8KcO7WFwg/xRLfxl198mbGSgzX5lM=@googlegroups.com
X-Gm-Gg: ASbGncui+d55zBl8DsLUZ6nxwtaIuWJ+r7E0xn86vFvF1VFM5moZKT1mwWqzE0SqYsM
	Dq7GUD7q8wwYHNH1aOsToP9YKBZBtW2lhSQmuZUTFZtG7NGgobCxvgQodgiweIPIArnIQlXUy/Z
	H8DV2OCJJPxyw5TcG07XC7J5dK1oMSckwPWM0p3WPo/crbUbKPFkeg7oPLFkca/g8kpnNMGz174
	7276ehBSrxPOB005hKdz8xes3gqwvWgxWOnuJdeg38hfkhBGYohociO08FC3WeOKVkn6IcjC/dU
	RQXNyzD0O0Rur6y8IcEKHILmYYFSNhIcdN2DvGi0aeIxzJoZ76lo4slyYnLnS5QyyXPrkwomdDj
	ut/pXEfTTyraFhz3JeqFXJE/wtk56si2LNjV0q0Zt3tWrUg==
X-Received: by 2002:a05:6a20:7f9c:b0:249:467e:ba68 with SMTP id adf61e73a8af0-2602c90cda4mr2342631637.50.1757656309414;
        Thu, 11 Sep 2025 22:51:49 -0700 (PDT)
Received: from localhost ([45.90.208.139])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7761853866bsm450111b3a.95.2025.09.11.22.51.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Sep 2025 22:51:48 -0700 (PDT)
Date: Fri, 12 Sep 2025 13:51:43 +0800
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	"Naveen N . Rao" <naveen@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, "David S. Miller" <davem@davemloft.net>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>, linux-mm@kvack.org,
	linux-trace-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org
Cc: linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 00/19] mm/ksw: Introduce real-time Kernel Stack Watch
 debugging tool
Message-ID: <aMO07xMDpDdDc1zm@mdev>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250910052335.1151048-1-wangjinchao600@gmail.com>
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=L96ka5hP;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

FYI: The current patchset contains lockdep issues due to the kprobe handler
running in NMI context. Please do not spend time reviewing this version.
Thanks.
-- 
Jinchao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aMO07xMDpDdDc1zm%40mdev.
