Return-Path: <kasan-dev+bncBCMIZB7QWENRBEGAXWGAMGQEM5ZUKCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id BC89A44F1E7
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Nov 2021 07:49:53 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id y18-20020a17090abd1200b001a4dcd1501csf5633729pjr.4
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Nov 2021 22:49:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636786192; cv=pass;
        d=google.com; s=arc-20160816;
        b=F0R+od7iYUgHDHtIyhqISoOYsm85h2/Ch5VK4yh6ciC+fqcvMTjBj+rvOpvHXtlCkl
         jB6PvT5zRyTnAA29X58I0gP+hVg49IJO6BV3WAFqxwQl6DCZ4rK03Ewav6RADmwsgt8H
         mbnOPe2pSJuzSB7VDjWvOybBpkmpbSCtnklnBc4gW+xN6Zml8ChpUJhJKBK03xo7edCt
         5dKfyMNnddjw+84+WgYFcsLS+3jNPkCRcjMfjA/XaWTXtmbKgMKtVIq8Kcha2r6jds7s
         w0WjgueH+woLyxg2BXzv2uTxqGao2bJa2/x7UnzDKuWBRM3VFwiYYK+tw52WDRWPT4W1
         tnOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=XK2ssCKCYYJGl71ak6X5QGfJKtGM+25uggz98vVfftk=;
        b=NQUvBSPBgvIZBVYPYfhHS08x44aHWRU5oWPTAJhvy4g1kxf7ms8SBvZqO5eNr1b2io
         Qew0pq0vV/PrLCt9QtZQm/8Y+YaKme5yFZtBCgWQbnAnZRDHzRH98zDTJU3v92fDDKox
         cDrWOHUzE4Pe2XzC4P1E4Tp5QnjtJ26kOdGKuhYPMwSgX6ymzf2cAlX2wATXgT96mP0G
         3TQiOXMyACQwtAFOWncvxBg9EVXIzkhPZ+gpMRScbDVCH0LxB6fnfUFCyq2QddIeF7xj
         gF0uQ1O5NvHwBp/M0Gr0cB3NRp/0LO9Q+7CcSsP+TkSnm6/T29qOt95zDlnKGVqfxqpV
         TpaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=O5ScEO9L;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c2a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XK2ssCKCYYJGl71ak6X5QGfJKtGM+25uggz98vVfftk=;
        b=hJHbSw5JGoznkDiS/4Y/nIJ4WSUFJO4NeiJnrIoqDcBiQV11qL6nUNtmiPKlymTRE0
         VlXhSsI3IlRXJOGHpQr427M19JRVUm93sPeKPsxJhJfaRSD+sgZAJqFNJ3vMmE7TEnR7
         c+4iN2uKUNFQUCT0a6OfmvdAtOF8xyXWZAGCX6bArrW45XOyQ1LiW+H3uP9G0ia8PxPW
         2ZoBvNRrGZBIU+H5+YBZ9QBUD5H/HZaADtfSWsr2IOIcd6hYg1qa7C6BylS2HenYr5v3
         gBcwkylLRnKNAXyKRplrBRKHRydhhNnQpM/soKzEPC97twxk7z7RBnHaRkTWPAyswV3z
         eHLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XK2ssCKCYYJGl71ak6X5QGfJKtGM+25uggz98vVfftk=;
        b=XpeR8/nRZPMDgZuhZ4p86Tw12WwoLF2PW3yL82KzKyLEbZI4jClVScZNWbpVL+tM+N
         vkvkXusDNQfnyddMfUQyAyTdD8kv3JbuGMRMl3DoIUcrLbBfkMeJ96B96zCY4S3WnYUz
         Kp82RCeLV+ZRy8bMF+5jX6H99JrQKVUZXgjqcS7KRaIWlUptGLGEUzLWM2i8EikyeJFr
         WF3jNfaAc/BkNeRc0Nrgx8aEEXsWWhm55y5MaT9vUH+mUHnIOF9jVVREg/heHeHQHYYq
         pIC/7TcpMUqQqDVZWkz9TPyxG0Kd4kwGFz7v4xsN/6Hex2W2VmwyUAJNcjVqPEF6Il4z
         O69w==
X-Gm-Message-State: AOAM531+X+Jy0k/9q6k+bMpbn2xH/wOXJu9Fl2MTr2ZzQEGBYRD8y9NB
	5xTXn+G+YCgrk23TZhlq2KE=
X-Google-Smtp-Source: ABdhPJy1MMwwz02ALrZVT0yMmzI60LsnyQzXF1Sdr9qOksBkCaiHG8tyteOJwuPW0MT8gz1MyOor+A==
X-Received: by 2002:a17:90a:c58f:: with SMTP id l15mr44205624pjt.75.1636786192545;
        Fri, 12 Nov 2021 22:49:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c40d:: with SMTP id k13ls5687143plk.5.gmail; Fri, 12
 Nov 2021 22:49:52 -0800 (PST)
X-Received: by 2002:a17:90b:4a89:: with SMTP id lp9mr43644947pjb.6.1636786191973;
        Fri, 12 Nov 2021 22:49:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636786191; cv=none;
        d=google.com; s=arc-20160816;
        b=vOvLi9dKutGCMIwNEg9Gx95uhOVpBRSBUBEOWOpqqCWG3ZxeIUNGTMPPHXigxsYjXN
         ZL40QtKUEBNUQDNPpuXQ9VSw0s7yls4sPMHqFf6E9IE3S1vAVfXD8e7cjNiYUoEYmZwL
         vJ0F7ADLvO2gVr8VtmQIMTXzBkfpd/kvaUE7NVH82qSS22oFjH3K964iuV2R+kJESIBl
         kC2GKgWu0mv3SP/Cm6ZhQAE/Kd21x0ySvUDrnMLvDp4XqWN+ISToDQ+mBoM313jEaw3O
         FlE0GXka18c1j5jEu48zK0DHkjqNB6aMqfgCvPC8uXOsRpTLOmdO3ZYcMYcqF/VN099W
         OdOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2csE+vfv+2C2Bz2Yg7KDQ9CqRXO/lvNFRQTf9C1HtyE=;
        b=AdN7I27gUx4nUCKjDHA0VhqB2bhyJZVXQHlgRWicrdAK5sJgCBRhEz+nAsqQ68bg42
         d4yYWKzYxipe77wlxn8f3/WsagP9dQ3NV/ZyfPpQcyq1MSIw+g5pwrsLKsrddhG4qrFs
         4ZByQHKx0DQgd/vKN5VAWdVwCoDJl3D65cG08oVYumNm8bZBnvmLiFrVMmdQ0LwKVBi7
         G7j4sD4sVWRCPwn6bvmCfQfiHWD7sSntlx2kcFWymW4C/5FNeh2p5FsyBtHnzzMv0aX8
         ve3BFoEEH1B7z8p0rDNg7kYsgd5vUgywy+hxpj4Ql0ZtMqUbXGpfIAG30DleFmkL/FAH
         0Jfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=O5ScEO9L;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c2a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2a.google.com (mail-oo1-xc2a.google.com. [2607:f8b0:4864:20::c2a])
        by gmr-mx.google.com with ESMTPS id mq9si821842pjb.3.2021.11.12.22.49.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Nov 2021 22:49:51 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c2a as permitted sender) client-ip=2607:f8b0:4864:20::c2a;
Received: by mail-oo1-xc2a.google.com with SMTP id v30-20020a4a315e000000b002c52d555875so2698714oog.12
        for <kasan-dev@googlegroups.com>; Fri, 12 Nov 2021 22:49:51 -0800 (PST)
X-Received: by 2002:a4a:d5c8:: with SMTP id a8mr11706781oot.18.1636786191098;
 Fri, 12 Nov 2021 22:49:51 -0800 (PST)
MIME-Version: 1.0
References: <YY9ECKyPtDbD9q8q@qian-HP-Z2-SFF-G5-Workstation> <YY9WKU/cnQI4xqNE@qian-HP-Z2-SFF-G5-Workstation>
In-Reply-To: <YY9WKU/cnQI4xqNE@qian-HP-Z2-SFF-G5-Workstation>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 13 Nov 2021 07:49:39 +0100
Message-ID: <CACT4Y+bj7JU=5Db=bAafjNKJcezeczzDCTwpKvhhC8kESc5+kQ@mail.gmail.com>
Subject: Re: KASAN + CPU soft-hotplug = stack-out-of-bounds at cpuinfo_store_cpu
To: Qian Cai <quic_qiancai@quicinc.com>
Cc: Will Deacon <will@kernel.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Mark Rutland <mark.rutland@arm.com>, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Valentin Schneider <valentin.schneider@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=O5ScEO9L;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c2a
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Sat, 13 Nov 2021 at 07:07, Qian Cai <quic_qiancai@quicinc.com> wrote:
>
> On Fri, Nov 12, 2021 at 11:50:19PM -0500, Qian Cai wrote:
> > FYI, running CPU soft-hotplug with KASAN on arm64 defconfig will
> > always trigger a stack-out-of-bounds below.
>
> Actually, KASAN is not enough to trigger. It needs some addition
> debugging options to reproduce. I'll narrow it down later. Anyway,
> this one will reproduce.
>
> http://lsbug.org/tmp/config-bad-14rc1.txt

This may be just a bad format string.
But I don't see kernel/printk/printk.c:2264 doing any printk on
next-20211110. What's up with line numbers?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bbj7JU%3D5Db%3DbAafjNKJcezeczzDCTwpKvhhC8kESc5%2BkQ%40mail.gmail.com.
