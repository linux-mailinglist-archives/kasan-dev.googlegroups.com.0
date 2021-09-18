Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4HGS2FAMGQEHCSXTQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id C6336410584
	for <lists+kasan-dev@lfdr.de>; Sat, 18 Sep 2021 11:37:53 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id c21-20020ac85195000000b002a540bbf1casf54009686qtn.2
        for <lists+kasan-dev@lfdr.de>; Sat, 18 Sep 2021 02:37:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631957872; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ex3xaNHMUUFahDwgmXM2nHBgbcERpaOUGMlBPd5MhlW1u9pieqSlpSRuKvyQs39Flc
         nhbJETiyJJVyEG2fhy1+M/9hbm6NWfg5g0Qfuvwf4Vy4djJJpAjSJrEiAfxKgd10sc7W
         IaOncsR44X7q6yqa/IDEXD8C3tJKtqV/v/1xeu8O+PxbOKvSKxVER1bGtT7rLNBJmOs6
         +2RXdk3vsGne+uZKFUfBG1ODTqqaROIR6Cr1FCza/4xpYROHD1vzCKaNGhmkFQjBxS/d
         DuhEkgItKxsQOZpvueBDhyjD+UdLi5WKTcRerCOtCwe/fF5BXg0d6VFL9dqky0jHeJ/S
         NGzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Fe/KEF5MvgbKLGITDd5wIDHNJ9NdGuEAh0Dw/HZPVrc=;
        b=EqW3ogk9rdH/JM+jLKEZxsKts11LaWNUanZtyBIJpHZoUYC8F0abeI7Lo8HagMG2c3
         VZtyj8wqPHApadi24PXqujXlIW/E40PbFuEmhQuC2l7dl2CTuabDSo83tv2p8ArgdHZb
         ObnU+wCzRIi05KugQFbd0vSETSLRc3LcmzP0aV6NLzCNmjaM9YBSsv6s3OAfp4qmV6Wp
         Ya87pfUvRnf7iLvRzRHKpuhfq4wTA/L4Bb/EEaCRqjyy4iL7G6GMU9W5IanLKYryDlHU
         H9RlR8NqfP/OVeQC8DiiASUDpMri7+Vun4mKIVKc3mQ58n9u/gGhY8005d94RNT8he62
         KNKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=f4ghaAsI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fe/KEF5MvgbKLGITDd5wIDHNJ9NdGuEAh0Dw/HZPVrc=;
        b=VtKXCI/fBtdBhoLglD97q8/UWAssM82fNUQRIcrxllmdHJ52hgC0Hv7pIGsF7NNH/U
         pLl0/FxnquhGaLTkLx7lzjsaLoWiQoVWJ4gHzPQ5lSErWn0XaS8KPOkZO57dqu3y9OX6
         AHHvTBlWeY55+5BEAIjsfzvkcGvQai6hgzegpn7u1Wwqb3z37W/UEtCv3wygRdB/zjQP
         mdO71m5hUDuRDhnfNw3TRZlohdCmMTYEvt3Io8h+qACZR6akL61zRFGjLcJLim4LiWZS
         +dh1gukIWg31OFmWl7X6EzJyCl8AI28bNFfx/rRsM2nz3DEVZrnq5Q4F/2LtGhFDM4OE
         SyZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fe/KEF5MvgbKLGITDd5wIDHNJ9NdGuEAh0Dw/HZPVrc=;
        b=EmPyVVoWTxnpzuXjjmNWacaXjQ0y2wV4nBCQ5xH6wBtH0UqySR8zhc+d4XlcUxXu23
         F44+WlickFSJ1l5GCOf62ILAmzSmP6Wnr478CKYWBqgIpl4iLJpsDjyRqOIDF15/Unfg
         Qyq3Bl7YLRxMCqMzZ8mkYbO8zHTDtzo4slaRLP/BA8aglXn2xxrxVkM535EpSvd+q0FK
         SJLDeBO89iNiLPO9cT5tZkP54++WQ6jfSoocrwvZsaC4mLR69nzTtdbVWkPKufegg1G+
         /BrYYXVRn2UPUu15NtvRm4OQEtD1XqZKpqYRcrYZ4EU5UbJy+/BjZ2HcvpeDoFM/xrF0
         J0vg==
X-Gm-Message-State: AOAM532LUpnXsSDyJcCNH9kfni5Kqz2vaY1W8kS7HMoY8Zbz4gxL3+c3
	EpU6T62c3+iiDJ8Pn6x1hKg=
X-Google-Smtp-Source: ABdhPJyZ/2f5a3F25QlytKD4tcNK0s0awQQwc15SKJMKkBXFKX9IwWdNBrLBLLESrJ2YzLCkSQU0OA==
X-Received: by 2002:ac8:7482:: with SMTP id v2mr14236919qtq.235.1631957872762;
        Sat, 18 Sep 2021 02:37:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a4c7:: with SMTP id n190ls10933987qke.4.gmail; Sat, 18
 Sep 2021 02:37:52 -0700 (PDT)
X-Received: by 2002:a05:620a:4106:: with SMTP id j6mr14644691qko.392.1631957872263;
        Sat, 18 Sep 2021 02:37:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631957872; cv=none;
        d=google.com; s=arc-20160816;
        b=EGiqKRJECiYchmCLDUJTphsQPp7yxOs0I2keInkMr4Hl1H2w5qIGySLSQkK+XWH9OR
         YPOtBhYJSW+z4UMs4puNgkpeqG7rQHvYMVE+FtabJWhjG6V5KfEx8ALC7CVKVTLM9L6Z
         HQq971ds2wgh7TFXUvOwbEnEm4UhA6k+/b51SsPmGQBnYeoWa+h9RmBs91HPBQYJHDwL
         ILVXMngE8ww35atBuUJKV3ua7fSuOjVir7pOcrWgz8Lf9qu7sXW7IREDp38vptBgjCjZ
         MsIutUk1Qblrz2AsqaRx/8UQtUaOR0WpwckQE56QSl6izoIvstF+U+rmRnkAHI5d91gA
         LZNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6h+x0dHkm1w/PqTQjkLPsLAB59NflCQjx0DuNDZvQsk=;
        b=oSJJVpUMYro10okkqYMVzFoCtGcNyM3VaumcAfmFo/+m7rKBoDTm4ySrwacRoKTDoz
         58oSAsx2nasKun928eG/+I7pNDiXRaJZHY0sN9KkqT81FJed5JhiJY4NBarrw7cXKexy
         lh4KQUzFy//N/zUo+hlnnHejaqQ/Hbn60MwGVJ6NnmnMUgdY5uzhwAR/eTlwDvJZoQCp
         y+ZmNKV52RXcCb0Zhab5C0u6EotTQc9PRJ/W7bmi36/CB8TmM3eVUtwEpNfT6PsqOSFK
         JBl00ywfPS+giM/KtKVf4c8SFGdufvyGiDvW32XZwEawuDdr9Ol3ZTFMePGjHB9vfvDr
         BrKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=f4ghaAsI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22e.google.com (mail-oi1-x22e.google.com. [2607:f8b0:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id a21si1361638qtm.3.2021.09.18.02.37.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 18 Sep 2021 02:37:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) client-ip=2607:f8b0:4864:20::22e;
Received: by mail-oi1-x22e.google.com with SMTP id p2so17618310oif.1
        for <kasan-dev@googlegroups.com>; Sat, 18 Sep 2021 02:37:52 -0700 (PDT)
X-Received: by 2002:a05:6808:21a5:: with SMTP id be37mr6918034oib.172.1631957871829;
 Sat, 18 Sep 2021 02:37:51 -0700 (PDT)
MIME-Version: 1.0
References: <20210421105132.3965998-1-elver@google.com> <20210421105132.3965998-3-elver@google.com>
 <6c0d5f40-5067-3a59-65fa-6977b6f70219@huawei.com> <abd74d5a-1236-4f0e-c123-a41e56e22391@huawei.com>
 <CANpmjNNXiuQbjMBP=5+uZRNAiduV7v067pPmAgsYzSPpR8Y2yg@mail.gmail.com> <da6629d3-2530-46b0-651b-904159a7a189@huawei.com>
In-Reply-To: <da6629d3-2530-46b0-651b-904159a7a189@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 18 Sep 2021 11:37:39 +0200
Message-ID: <CANpmjNPj5aMPu_7D=cwrDyAwz9i-rVcXYgGapYdB+vdHcR3RZg@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] kfence: maximize allocation wait timeout duration
To: Liu Shixin <liushixin2@huawei.com>
Cc: Kefeng Wang <wangkefeng.wang@huawei.com>, akpm@linux-foundation.org, 
	glider@google.com, dvyukov@google.com, jannh@google.com, mark.rutland@arm.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	hdanton@sina.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=f4ghaAsI;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as
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

On Sat, 18 Sept 2021 at 10:07, Liu Shixin <liushixin2@huawei.com> wrote:
>
> On 2021/9/16 16:49, Marco Elver wrote:
> > On Thu, 16 Sept 2021 at 03:20, Kefeng Wang <wangkefeng.wang@huawei.com> wrote:
> >> Hi Marco,
> >>
> >> We found kfence_test will fails  on ARM64 with this patch with/without
> >> CONFIG_DETECT_HUNG_TASK,
> >>
> >> Any thought ?
> > Please share log and instructions to reproduce if possible. Also, if
> > possible, please share bisection log that led you to this patch.
> >
> > I currently do not see how this patch would cause that, it only
> > increases the timeout duration.
> >
> > I know that under QEMU TCG mode, there are occasionally timeouts in
> > the test simply due to QEMU being extremely slow or other weirdness.
> >
> >
> Hi Marco,
>
> There are some of the results of the current test:
> 1. Using qemu-kvm on arm64 machine, all testcase can pass.
> 2. Using qemu-system-aarch64 on x86_64 machine, randomly some testcases fail.
> 3. Using qemu-system-aarch64 on x86_64, but removing the judgment of kfence_allocation_key in kfence_alloc(), all testcase can pass.
>
> I add some printing to the kernel and get very strange results.
> I add a new variable kfence_allocation_key_gate to track the
> state of kfence_allocation_key. As shown in the following code, theoretically,
> if kfence_allocation_key_gate is zero, then kfence_allocation_key must be
> enabled, so the value of variable error in kfence_alloc() should always be
> zero. In fact, all the passed testcases fit this point. But as shown in the
> following failed log, although kfence_allocation_key has been enabled, it's
> still check failed here.
>
> So I think static_key might be problematic in my qemu environment.
> The change of timeout is not a problem but caused us to observe this problem.
> I tried changing the wait_event to a loop. I set timeout to HZ and re-enable/disabled
> in each loop, then the failed testcase disappears.

Nice analysis, thanks! What I gather is that static_keys/jump_labels
are somehow broken in QEMU.

This does remind me that I found a bug in QEMU that might be relevant:
https://bugs.launchpad.net/qemu/+bug/1920934
Looks like it was never fixed. :-/

The failures I encountered caused the kernel to crash, but never saw
the kfence test to fail due to that (never managed to get that far).
Though the bug I saw was on x86 TCG mode, and I never tried arm64. If
you can, try to build a QEMU with ASan and see if you also get the
same use-after-free bug.

Unless we observe the problem on a real machine, I think for now we
can conclude with fairly high confidence that QEMU TCG still has
issues and cannot be fully trusted here (see bug above).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPj5aMPu_7D%3DcwrDyAwz9i-rVcXYgGapYdB%2BvdHcR3RZg%40mail.gmail.com.
