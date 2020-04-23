Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBNXEQX2QKGQEWLIWWRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id A39211B5989
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 12:47:19 +0200 (CEST)
Received: by mail-vk1-xa3b.google.com with SMTP id b137sf2467910vke.18
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 03:47:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587638838; cv=pass;
        d=google.com; s=arc-20160816;
        b=FrHTZzwIzp+VxtPNgrCn/mgI6reXfwajAzkO45+HzckcLbUilvv3G8K2zDNj0nXGI/
         oyIuVfVo0BLuBNcdU5zMK+n3T6JkR4dEbGiEB/LuDeFU427QFaI3uQ7xolOXL82H7ZwQ
         kxI2s/dffLSNcQhtAKHRU6v94e57XzoE4Q7fL3CxZBcsZjj9vgS6DaH3iaptjE2biea0
         mE7YcWxrTsVtBKUI+7a525uuMpl8P7mYo9jC1wUXYRtB0A/GwfBJ0F4qeeIPyX8H65W3
         CoL1ASJPlrC9gsj2ry1uxS4ryX8mGDy2PLRIJH7x/51y2NmVhl5le64Q5UuSf5HmmcTi
         ItaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:sender:dkim-signature;
        bh=w7WOj/iJqWtKgW7/L7bNkhLC0pUAbhivQqn7qFagVoM=;
        b=XgmExTz/DwJ3oi6kP2dKSywZtYu+ZGlYPS718z/XsRtldaLd95fTlBOQnxBNvZ8Ahu
         ULUDYu0x39PkYanK7fqrYsRyc0tOoIDe4Vdk+kH9pPRd3yLqWJ4nLMk4VpXbQ971L4lK
         LpjBhm/sS8Z2EaVp3aatQowVM4x560pYgaAbHMfRQBv8LiG/15kB81LkdIJM3A9hkiw9
         3WfYVM2M00+r0MA9HIZfGfNPEEs877ozQE0PvbeMjs699Tqkhwy8dvMGFwQ2ZSWRB/P1
         wx6EKnNW+hSU5esdtaOLcKqLjrckrz13cNU3l+xWQog8YuOf/UNObBfHQYSngWOLKPVB
         kGww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=eHTRPV1A;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:mime-version:subject:date:message-id:references:cc
         :in-reply-to:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w7WOj/iJqWtKgW7/L7bNkhLC0pUAbhivQqn7qFagVoM=;
        b=YWLhle6YKDTSCMrLR4HPpWmxz57s5NzshB4xYu2o9XHtk8sbYRP69rGlg9LM7Qpm3v
         qXO5AYzBedWKmNQz6I9WEKsRHXjoQRuSoBmR46do5F4o6pJiU1vIGl1SVsOP8Gk6BfDI
         zKhGYP2RVSr25S3dstXxtQU71Reo3PN/6sneWfr1WUP6rF4AqL08W6aQUiOjm8/D/w+i
         ho74BtUvP4RTlT8NcNp2/7K7wWSZDpqxqjmknSorP5viTYNJ6bFqTbzVqQLDSx3SSMl9
         GsyThZxSUZk6txgwWC8stVNihmjJNtYu9i1r6mz0SqkG9ScFBE/50PnXwlSnpTIuNpzG
         Rn9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:mime-version:subject:date:message-id
         :references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w7WOj/iJqWtKgW7/L7bNkhLC0pUAbhivQqn7qFagVoM=;
        b=LgjMGRaPZ0ZB/5yVvcKK0wvRv5Hl5lw2YK4PBKnaE4/AqnM1pVye+BxfZ8daLCQcez
         niPQcYs/Hw+TO0HA91yIrOgpDvRTegFmIHJgmtfUJodI1fjdMClWWHaZRaiAuhNlZZUO
         8xR2stKOGCQA+y9RQyXWkcDQWOvgczNyJS2WXhYIen9/0QngvDsyHjTtIsemVi1mF0vL
         5Cb0cbQJolXLAn3VHtbGZnwTVkcUx24m+0MU/0jJ7F5GyOssPj8Mexq1RzUTuwuUtBPm
         TtzVywDphs7DDkK9SZhOJ1fCiPKfROS8qnVgFrrD2qf2KHSzgRP5zMnzhDcgYjX+ZLs+
         jgbg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuasxFl31Ddr3lErJp6vM5BXeWO3tV7Teo00see8JYyBEh4m9RGg
	/xrNXG4q7wuvXRLYXCCsQS8=
X-Google-Smtp-Source: APiQypL+OrBxGkee4qtRcFDDFSwox9yQguCHfknk982phqQG9yAwCu3zWrpFi9so0hgnJYYtv5Zw3w==
X-Received: by 2002:a67:e94d:: with SMTP id p13mr2414593vso.215.1587638838403;
        Thu, 23 Apr 2020 03:47:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2844:: with SMTP id o65ls779044vso.8.gmail; Thu, 23 Apr
 2020 03:47:18 -0700 (PDT)
X-Received: by 2002:a05:6102:7ab:: with SMTP id x11mr2278881vsg.91.1587638838001;
        Thu, 23 Apr 2020 03:47:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587638837; cv=none;
        d=google.com; s=arc-20160816;
        b=piFgn2QMafBf5DXPjtVFxTOop0LhWnAvLI5wtAKA2BKqXqxxBokKSg+XymkG/XXndw
         Z8+J3D8pleCNealJGCVP9Trlylk21sryMb5i6Dt8ijH/o30pWGXUWdHrIQPybtJ6+1wA
         UC9sy4lFXmjsZJw3O0vA1HI7IKqXX8JD2Khw16sK+IpxT65PL5XI0P3W3m3MscBk51tr
         xSLbFCN+bOeq37uZ3IQ1FE0mxCHsik9RI+mgHJ/M/GDAVMKCFIMRR2VUImDwPJgkA8Ah
         KNGXS/xG+6Nbc/KkO3Cli+r+UGwnbLhd8dyNdeY2fYzL/I2EaDeuOOcQlA8bbLC4pO6x
         n9jA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=bBc1CHMMP5ULsArwb7u9wHSPCs7CVoGv3bVPmYv/xJc=;
        b=Eu0qeXS6uV6u2hmVoyGvWYUvReM/WYsrza7YYf//kcJ+oZrgxgM6lzKV5ApMpok198
         Rr0SotXhYz1mRAqULsMa4W+bWkTcm3lP6LiQApmLuQGkmzUZhyraJQltpTFGAuqLG3jk
         dZWpKNHNl1QzTan45JCo8frngXqbQz96nLEyjc+Nf958RV1ktlZMszB4Upled4e05Dyl
         /bguFPtVBTVqcIXK52nSVUOXGxB6yrP2YSTMlfEJnh6K/SDT2xYIMChrM37DWXKsu/6T
         LbEtxYzC00Ezt+yALnQDbSAOoXhRjIj4yqYYzDK0GactblY7k8Vk2w+nvSFrfmZsW/L0
         zV8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=eHTRPV1A;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qv1-xf2f.google.com (mail-qv1-xf2f.google.com. [2607:f8b0:4864:20::f2f])
        by gmr-mx.google.com with ESMTPS id f17si169801vka.5.2020.04.23.03.47.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Apr 2020 03:47:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f2f as permitted sender) client-ip=2607:f8b0:4864:20::f2f;
Received: by mail-qv1-xf2f.google.com with SMTP id 59so508021qva.13
        for <kasan-dev@googlegroups.com>; Thu, 23 Apr 2020 03:47:17 -0700 (PDT)
X-Received: by 2002:ad4:54c3:: with SMTP id j3mr3441613qvx.241.1587638836915;
        Thu, 23 Apr 2020 03:47:16 -0700 (PDT)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id g4sm1395543qtq.93.2020.04.23.03.47.15
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Apr 2020 03:47:16 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: AMD boot woe due to "x86/mm: Cleanup pgprot_4k_2_large() and pgprot_large_2_4k()"
Date: Thu, 23 Apr 2020 06:47:15 -0400
Message-Id: <838855E1-35B4-4235-B164-4C3ED127CCF4@lca.pw>
References: <20200423060825.GA9824@lst.de>
Cc: Borislav Petkov <bp@alien8.de>,
 "Peter Zijlstra (Intel)" <peterz@infradead.org>, x86 <x86@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
In-Reply-To: <20200423060825.GA9824@lst.de>
To: Christoph Hellwig <hch@lst.de>
X-Mailer: iPhone Mail (17D50)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=eHTRPV1A;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f2f as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Apr 23, 2020, at 2:08 AM, Christoph Hellwig <hch@lst.de> wrote:
> 
> I can send one, but given that Qian found it and fixed it I'd have
> to attribute it to him anyway :)
> 
> This assumes you don't want a complete resend of the series, of course.

How about you send a single patch to include this and the the other pgprotval_t fix you mentioned early as well? Feel free to add my reported-by while all I care is to close out those bugs.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/838855E1-35B4-4235-B164-4C3ED127CCF4%40lca.pw.
