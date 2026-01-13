Return-Path: <kasan-dev+bncBCJNVUGE34MBBIFBTHFQMGQEXAHVKLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 498C9D1942B
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 15:03:14 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-81f46844106sf2104161b3a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 06:03:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768312993; cv=pass;
        d=google.com; s=arc-20240605;
        b=WQY9PU8q9ZLGdED9hojJ0UlKHXIrhwYVOzhpNAwDK9jzShS2qVl0djogRibmpd2IAs
         vDUCRgztE3TaxZTG4S0TMV46z79YB3RL6bVy25o50mAKaPg/xB1tCjUtMm2IcZ0VZ4Lj
         707i3OPfbdXMtt/AtiX5a8OgtpNxR2Ic+0fCe2Zj2GNlaj8j9vGXIUlt9SwLAmRSUzEP
         ARG0ckyXOvrAViYCBlyw0PcznAF9UsxONgABbOc6DS4dabspCLFQnYiNz210gcDXl7R5
         UQ5jjiob771yHpfY8qeyHlV1ExUGE++oAWs0Mmavz8Dh5LnNJ9kAJffLvT1FzD/W9NjN
         CWaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=j8tunDIQBUa8yVctI+Q6PoX1+o2FGjhAOLdJyVhqYnE=;
        fh=ADDoENlvq2KBrIDsGJ+Gslqrbik7Ffc55WtHAwy0nr0=;
        b=TscHIoemTYMvEmIsVdgR4urjC73dwf14eXmhRChqMHEgPsoFBEjTb9joJROi4OxysF
         F16lHpEFQxcuFRGitPVJ/QAQXea+Wk5owiQexq8RyJY7VBilRbiVqY1Tm2zXQGrdBb6a
         8Gn+lmpda9u3kZIa9E/lB2wM7IaZuL8s/4xrpB9qo859gnWN1HHcZAiie90Aut440rND
         tuGRAXlwgofrkdJsCttzfxq11TKgytdRAvaS3OOk9kwe20uaWGC0cmIbx5Sq9Pd3Y+Gi
         yKVbMf3Bf8TSqqLgIB2cw2fw22SVXkg4/vM70UFE8I56nieEM5WTO0bJnQygABPdIfTR
         aLuA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@meta.com header.s=s2048-2025-q2 header.b=I0duCVe7;
       spf=pass (google.com: domain of prvs=9473463a0e=clm@meta.com designates 67.231.153.30 as permitted sender) smtp.mailfrom="prvs=9473463a0e=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768312993; x=1768917793; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=j8tunDIQBUa8yVctI+Q6PoX1+o2FGjhAOLdJyVhqYnE=;
        b=qwJaX3OGM4Ou8BOaSXwyVy3x2j68zEpNKxUHJkvAhiioDoQk5zUSgQmsEvRo2QOGex
         rnP5L+k89SjiN1xWGDqAbfCszCuXBxhgSvL39SFOOnfvhxWbxLfW5eaadvQHOUgy5ewr
         iB8kGh9pOrOkmn3g5BnFb0HrWYcfGztIKLKQDT5QTjFevWAa6ctJ7kZfO4m/+w+2ikfY
         bjbRY3n75GxuozmMyoMic067RwXlMkg82Tb5+f3zx6aexuU75SQFvmwME3MxeVYOHqFx
         DK8NK7GXW2/ToTVasLWC1N6/mM4DtgrfxCQKf8ZNTWDG8coVCTkTaG8S40Niad3bTgKq
         egIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768312993; x=1768917793;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=j8tunDIQBUa8yVctI+Q6PoX1+o2FGjhAOLdJyVhqYnE=;
        b=HPomcFwS5/eYFVfq9W40OGSKrI8mFOF/Wed12aZ6LW1PwuHd5sKCZ2vr3ul3UHthEs
         f1bS5c9i1ETB0AKqFBrDYr0zTd9s/sY81XbLZLLBRDz55qXf3D2LFbeyhQb39av9DgPX
         fayxQT4xJ/rHzwyROvG4U/dwhJeW90oWagHI5Okg3jyE8NMISN1y3asxYg/8srHNtgR6
         1EBVacc3YRZ1pH65qvfVEcF00ZpvH+HpeywgsrNtbG+C1+fdX5dcwW3i4fZg+YVbmbKg
         NyA9e2gfvlm2gsfIvZN3XdTMEYbPQ78Iz4ACnHD9nhzuaBXmU7zc5PZd19xbaKfjEWwS
         +tKg==
X-Forwarded-Encrypted: i=2; AJvYcCVQ+F2UHb6NPzKKm4i0SyYIEq8g9brWWtpt85W22iscfBw/52Q3HSUZWfUAIlTHR+L/OwhWxQ==@lfdr.de
X-Gm-Message-State: AOJu0YxuA28CNjUTvH7K9FAZAxbMLJC1lKtREJbcmHKV78V34Xm5BvHY
	bSZKF6+vGKdjtHmRex9ASQxSGd33BaymjgJjEx7iDV2NAMIK4wNL7taL
X-Received: by 2002:a05:6a00:2f18:b0:81c:94f1:7bc4 with SMTP id d2e1a72fcca58-81f6f2caa5dmr2078183b3a.0.1768312992422;
        Tue, 13 Jan 2026 06:03:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GX+ynk71MpS+W1hYTL28t+vAqV5mGKZrhDj2Pz6gskqg=="
Received: by 2002:a05:6a00:32cb:b0:7f1:4219:37f2 with SMTP id
 d2e1a72fcca58-81b79aec715ls3486383b3a.0.-pod-prod-00-us; Tue, 13 Jan 2026
 06:03:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUvjW5boY6swHzwupW0QVwljf65xbDsRSoGE7DDs0vsvYP81jruuZIiIBWqTUWuX7DD5IgPtc2KGUI=@googlegroups.com
X-Received: by 2002:a05:6a00:4087:b0:7e8:3fcb:9b09 with SMTP id d2e1a72fcca58-81f6f821d67mr2737925b3a.31.1768312989811;
        Tue, 13 Jan 2026 06:03:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768312989; cv=none;
        d=google.com; s=arc-20240605;
        b=dWdu5PFj3fF51ndTm/Nr/2C2L6TV6ZGmjqcnlDUEPd6N4n0Y8aZONM/qNR5JiL4B9Y
         CCK5Lu9qoz5/wYNpCoardGkZXsPxcM2ld6lmNAB2n7fI2IZtXXKszHB4HYK9U28AH7Hm
         MbiXBW/5fukcA05NDiBo5AZSG3HI7veYmDd9rHFZIyDrNDT6DtbXKxhj3MOw0iLwWYsI
         Ss7eDwPNQLb4BR3N+kknTPMqMRdaVwxs0L9tTl49hzvvqS3iZGZlZlpz8w+1r07wksEg
         QupenAKebLsy9dnbld2N6qqLo3xcsIbl+ppLf88COdAT7FZVxSwimt2K5JV+Sk0ynICH
         PWfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fQ7j1PpGTasQAblfO8V1KwLqMUsTQm5W+M3/6xbpbQs=;
        fh=TVqdeorLdnUWQDnnl8adXN63/AOv77UePQtKSxiRlsg=;
        b=fu6rm1CkFKD7c3Zj5zndh7XCGNZMxS7zL7yjICJKUGdp8qdoZXXRVYAQsM0poG/1xS
         phDVCOVFynpyLbYMTZ9TyW7tBjYIqonbuljV73i9D+8Z7yrdGPm/wbjM5ULZ9GqIbtGs
         sISAdjEe763w/BaWLB3i/wHeh1ltvvwLXKV4W/h/IGV2+f2l01tIh4Yy6VGjoD+hKmCu
         BDSm0NXK6VdUHJ1uY3aUiIDsQ7MKdV2lrp7yyxkdqwrJjFB/6TojYoKFjzztD498wBf+
         EMQOzKU8Y2SE48QRI6sAlPVM9OYkC98bfLuX/v4fVHDgEtOhXvpOmq484qtyfMpz1mOq
         kgLw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@meta.com header.s=s2048-2025-q2 header.b=I0duCVe7;
       spf=pass (google.com: domain of prvs=9473463a0e=clm@meta.com designates 67.231.153.30 as permitted sender) smtp.mailfrom="prvs=9473463a0e=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
Received: from mx0a-00082601.pphosted.com (mx0b-00082601.pphosted.com. [67.231.153.30])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-81e6389934csi354136b3a.0.2026.01.13.06.03.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jan 2026 06:03:09 -0800 (PST)
Received-SPF: pass (google.com: domain of prvs=9473463a0e=clm@meta.com designates 67.231.153.30 as permitted sender) client-ip=67.231.153.30;
Received: from pps.filterd (m0001303.ppops.net [127.0.0.1])
	by m0001303.ppops.net (8.18.1.11/8.18.1.11) with ESMTP id 60DC4dtS1330592;
	Tue, 13 Jan 2026 06:02:54 -0800
Received: from mail.thefacebook.com ([163.114.134.16])
	by m0001303.ppops.net (PPS) with ESMTPS id 4bnnr4rsm8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128 verify=NOT);
	Tue, 13 Jan 2026 06:02:54 -0800 (PST)
Received: from devbig003.atn7.facebook.com (2620:10d:c085:108::150d) by
 mail.thefacebook.com (2620:10d:c08b:78::2ac9) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.2.2562.29; Tue, 13 Jan 2026 14:02:51 +0000
From: "'Chris Mason' via kasan-dev" <kasan-dev@googlegroups.com>
To: Breno Leitao <leitao@debian.org>
CC: Chris Mason <clm@meta.com>, Alexander Potapenko <glider@google.com>,
        "Marco Elver" <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        Andrew
 Morton <akpm@linux-foundation.org>,
        <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
        <linux-kernel@vger.kernel.org>, <kernel-team@meta.com>,
        <stable@vger.kernel.org>
Subject: Re: [PATCH v2] mm/kfence: add reboot notifier to disable KFENCE on shutdown
Date: Tue, 13 Jan 2026 06:02:27 -0800
Message-ID: <20260113140234.677117-1-clm@meta.com>
X-Mailer: git-send-email 2.47.3
In-Reply-To: <20251127-kfence-v2-1-daeccb5ef9aa@debian.org>
References: 
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [2620:10d:c085:108::150d]
X-Proofpoint-GUID: -zdoFufYx-ri54AmF2W0YNzuIqDQSvvM
X-Authority-Analysis: v=2.4 cv=Zs/g6t7G c=1 sm=1 tr=0 ts=6966508e cx=c_pps
 a=CB4LiSf2rd0gKozIdrpkBw==:117 a=CB4LiSf2rd0gKozIdrpkBw==:17
 a=vUbySO9Y5rIA:10 a=VkNPw1HP01LnGYTKEx00:22 a=xNf9USuDAAAA:8
 a=7sR78lRsTtdWeVkM5_EA:9
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTEzMDExNyBTYWx0ZWRfX/SH2AzbaA7MB
 fQ7SM27TcoFfggUzHtqIj9YhlO1KEvX/6zhNr8J15aiISa2bEPfqhMxaGMCXMRk7HSSy2FeKxgG
 ibIbIpNHOjRb942E+A/vtvrrW00uQh/2JJikK5QORViYber7Xv8570VWucIgV+Md40nWkQ69a/h
 ceE9JyquvWsfNEG0ymemR3nJfJdFJBhdrqkXF+G4N4dEF3wCYQe9ChjlA5DEOg/VBgeqsjnHq9+
 fDMjeZ5zQVSoy9peZ/++qafLhPPJoHlPHTq/hJ0FOwRdkNTQolGhAI5ikEhdq/6EtAbq6PscK5v
 U8+EjxbMMiTCIYMGLNF4UFv19e8DLo/fL3Mi2lZ+aEcSiIj70a/thIH9S26H8vTe2EGUs5jZ5uX
 tgvHiHwvc/8cojlBjhfmCefn7NaWbU4n/GkF4BpbvDEnVF+bsNROvOPUAnaRQjlW+R9I+QaCBm/
 M6FkDwYwMQY3kxIZ3GA==
X-Proofpoint-ORIG-GUID: -zdoFufYx-ri54AmF2W0YNzuIqDQSvvM
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2026-01-13_03,2026-01-09_02,2025-10-01_01
X-Original-Sender: clm@meta.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@meta.com header.s=s2048-2025-q2 header.b=I0duCVe7;       spf=pass
 (google.com: domain of prvs=9473463a0e=clm@meta.com designates 67.231.153.30
 as permitted sender) smtp.mailfrom="prvs=9473463a0e=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
X-Original-From: Chris Mason <clm@meta.com>
Reply-To: Chris Mason <clm@meta.com>
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

On Thu, 27 Nov 2025 06:51:54 -0800 Breno Leitao <leitao@debian.org> wrote:

> During system shutdown, KFENCE can cause IPI synchronization issues if
> it remains active through the reboot process. To prevent this, register
> a reboot notifier that disables KFENCE and cancels any pending timer
> work early in the shutdown sequence.
>

Hi Breno,

I'm running v6.19 MM commits through the patch review automation and this
one was flagged.  Is this deadlock possible?

Automated review output:

> @@ -820,6 +821,25 @@ static struct notifier_block kfence_check_canary_notifier = {
>  static struct delayed_work kfence_timer;
>
>  #ifdef CONFIG_KFENCE_STATIC_KEYS
> +static int kfence_reboot_callback(struct notifier_block *nb,
> +				  unsigned long action, void *data)
> +{
> +	/*
> +	 * Disable kfence to avoid static keys IPI synchronization during
> +	 * late shutdown/kexec
> +	 */
> +	WRITE_ONCE(kfence_enabled, false);
> +	/* Cancel any pending timer work */
> +	cancel_delayed_work_sync(&kfence_timer);
                   ^^^^^^^^^^^^^^^

Can cancel_delayed_work_sync() deadlock here?

If toggle_allocation_gate() is currently executing and blocked inside
wait_event_idle() (waiting for kfence_allocation_gate > 0), then
cancel_delayed_work_sync() will block forever waiting for the work to
complete.

The wait_event_idle() condition depends only on allocations occurring
to increment kfence_allocation_gate - setting kfence_enabled to false
does not wake up this wait. During shutdown when allocations may have
stopped, the work item could remain blocked indefinitely, causing the
reboot notifier to hang.

The call chain is:
  kfence_reboot_callback()
    -> cancel_delayed_work_sync(&kfence_timer)
       -> __flush_work()
          -> wait_for_completion(&barr.done)
             // waits forever because...

  toggle_allocation_gate() [currently running]
    -> wait_event_idle(allocation_wait, kfence_allocation_gate > 0)
       // never wakes up if no allocations happen

Would it be safer to use cancel_delayed_work() (non-sync) here, or add
a mechanism to wake up the wait_event_idle() when kfence_enabled becomes
false?


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260113140234.677117-1-clm%40meta.com.
