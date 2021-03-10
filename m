Return-Path: <kasan-dev+bncBCRKNY4WZECBBDPOUCBAMGQEVBSIPZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id D73B2333381
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 04:03:42 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id t13sf9643548pfg.13
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 19:03:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615345421; cv=pass;
        d=google.com; s=arc-20160816;
        b=yndLelT5dcWASex2dKNG6YJry0NR4ueapGiP/zI1VPoLFLDF7KD+ieevmK0jhCoTuh
         z1UEaXj//lcda0NXPXRv+Qg1xvg6UZ4EGWA2+KM7xDsG4IMCAK4ByPwF0KFXbDi7ST0V
         GBeq17BqyXW8DkAdN9L4QKImjVD8jejdwIGdRoengFTUk+zygZrdXZ14kiK9NtxLTvIC
         /nbgBtpB4qflTnwUUlJzxGcbfbPKyd4fLmBgrxXp/5H8FA8OiAe6mBRy6vekrxLat9DQ
         nSRqf5mBtTRTE/Ubz4osHxBq2nTIao8rvEcgy0T0bOx/E5R9P5NTpKRuAQZWNEzJUlwd
         pvoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=e3AGJhVGxZX3fogmI7Gnv6GkjZVs3B518Smo/YI9rrs=;
        b=OhVykfhWNLAPmkhq75B8wJSkXi01m3BqzLr/oq/ybC76rO8vJ1uaP8vVXUuY7CxatW
         J+Hu5rySnZXDXlUd7CzluLoWcajPwVqosj+AyQ/Z0LUKS4SvoUkSFnry7z1pE5TH+gW8
         qsWedbS2yUoV6RrqueLHd2ziTMu03jZoLQ/OPa5W5OCPiDBw2knBLX+aaso5f6uDlVk7
         cIbQzfOVKJEyO9chiBwS5vvQR9u32XnuOueGAKJ9ToIp0q5qeZxgJjtgv9BSqATjfW8u
         c/v65X1Epqu1A9s23sIOL5QSXRoe2yrwBdfUEnawKp8wwMmbwbAJItrHv0DDGcSWFP9V
         yfOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=XdXjc9K0;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e3AGJhVGxZX3fogmI7Gnv6GkjZVs3B518Smo/YI9rrs=;
        b=AT9s6338OFNxWZgHBJ3B34/Ybr+p8j9/TkByc3Uh6NAUEIGQT7XE6LjzG8/5KZEIMj
         2cN/9QqA9cMxLyEwwFIPZyxNlc67ubS2tCJXvCa1yWIZP5OiilLU5q7hx1yljkxGaRbZ
         6vg0LzguSbDHJAtniKTJoW2M6mXiW/AUoja0WfIPkXv8EnanjmFsDCaqZF7i5okJ9eCt
         Qy5uoMAtYrZApmDbeYD7mbojmjs7FOUK8JDcLGOJ+o66MrOLqwO6CN0VtCFZL7P3MO99
         bP4DZzQ3hvlkA74FZZqILTPSaphqCdhvbMny72t92MHEnR/s2WfgrlqWMhNIgzJio1Xb
         8Frg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e3AGJhVGxZX3fogmI7Gnv6GkjZVs3B518Smo/YI9rrs=;
        b=XgyLee2ZtNKGTN1twIF/MR5fvsaho/AyoeeWE60pMLzaOJMgvW9ojAfiAbANVyGrNF
         lT3rq/BE4hamK7eV0sPq6koWcSc5vBAQZHfRHBb4lTgdFvKLmo6wJnR7r4fol0Os5vDT
         9jaw2ZGLppI1yCWZzKicV/0H1iXvFAk7GU5J4IQXhgUltH3X9EMZZSGH5XEe8kguOCdj
         JCQquAKdX0VY1GA/+PtvXWZbfGNRsXq9xIQzlXuOHJFWK5K1IINVsurbH+mtpB9c5HJl
         vcc/l/V5CBzqg58fcoF4Jur3X6ydn67cgS7/Wq30RABNsXktc4/ENsFCXQIIbV8NnQOR
         C/Pw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533EpLlF+zNkhDngwSSnpOAeHCeHAZ89x8XPjJB+IffBuovaN6jG
	mFAA+3ttSCV5N5e7cYP080Q=
X-Google-Smtp-Source: ABdhPJwdZZ6XImPbpn85R9rEhlGO5iYoUkTveWwQ6xvRiKOMXK0Qwbsx9nkcTXsUm4osszj6jVfXKw==
X-Received: by 2002:a63:ba03:: with SMTP id k3mr890418pgf.274.1615345421564;
        Tue, 09 Mar 2021 19:03:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9106:: with SMTP id k6ls543536pjo.0.canary-gmail;
 Tue, 09 Mar 2021 19:03:41 -0800 (PST)
X-Received: by 2002:a17:90b:508:: with SMTP id r8mr1182992pjz.83.1615345421037;
        Tue, 09 Mar 2021 19:03:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615345421; cv=none;
        d=google.com; s=arc-20160816;
        b=WAX8/qrQ8oFtuOQR/1ACeAggXicRfKnJ4iuzELkIq14s6HWFNY7MqJtDGjYkoUReeZ
         2NNyQnyO7xyarQvkOumdch1YYELQF17MQsJJ/ptO+SduGBsbM56K/0EL9d1ZigFHghzN
         fZny196xrF1uZdlnpRlJYOlI9z7C3xlchbWNfB2MNkpkgI7B+VHrWMB4FOP87lTxSlPw
         ORrYcUpBf3MoszBhyER9tmKnQsFK7FQLKTTN3x7pvEkDN2xBGySE04/DffEhSD/vyjft
         X3vvKj02eE4MAaEPBQ4RX2QXVXdEJnDSvkZkzSLJLdqnDns08Y11OMNRloNuPQruagaq
         Uv4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=1YN8IaUR1Mu+1HOs/O2B0D40c+eC0rZ/zq/HTR6lO6w=;
        b=HuWOwxsLjs3PmtYNxA2ctw7R0jDXYF+sKIc46UqYlHoBxUf9C25LrJKML2JNPHm1Jn
         xQ5uMs7ig3tZ9j7Juq8F1vmqHRbs5jC7zkructPFhsD+GzUM3jGA5gEwMyQRB+ZpSdQx
         jK9U4tt+LIv+mrzjuRoep6xvpxNpvzhy+sv7CDfrukOsPNpFCrKAqn8zVqPr8JrYMuZc
         hYxk2/KKcRAidR1Tp7WSfjhfU/w9MWMDZHuSvDfK/ExVCO1kadwFLCsuJBsdaaRRxBd9
         +/3XqEEMmOy08FszQtkEI/nCJ6W/OV/o4Y7XIWghnBdB8rNqiO1Hk6bxzEJ+KJbIOjig
         O8Pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=XdXjc9K0;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id mj5si283980pjb.2.2021.03.09.19.03.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Mar 2021 19:03:40 -0800 (PST)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id p21so10410057pgl.12
        for <kasan-dev@googlegroups.com>; Tue, 09 Mar 2021 19:03:40 -0800 (PST)
X-Received: by 2002:a63:6dca:: with SMTP id i193mr879023pgc.81.1615345420644;
        Tue, 09 Mar 2021 19:03:40 -0800 (PST)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id s22sm4168279pjs.42.2021.03.09.19.03.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Mar 2021 19:03:39 -0800 (PST)
Date: Tue, 09 Mar 2021 19:03:39 -0800 (PST)
Subject: Re: [PATCH] riscv: kasan: remove unneeded semicolon
In-Reply-To: <1614667008-22640-1-git-send-email-jiapeng.chong@linux.alibaba.com>
CC: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
  dvyukov@google.com, Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  kasan-dev@googlegroups.com, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  jiapeng.chong@linux.alibaba.com
From: Palmer Dabbelt <palmer@dabbelt.com>
To: jiapeng.chong@linux.alibaba.com
Message-ID: <mhng-c78e0139-c0f9-4a61-87ab-f9658bfe5a42@penguin>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=XdXjc9K0;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Mon, 01 Mar 2021 22:36:48 PST (-0800), jiapeng.chong@linux.alibaba.com wrote:
> Fix the following coccicheck warnings:
>
> ./arch/riscv/mm/kasan_init.c:217:2-3: Unneeded semicolon.
>
> Reported-by: Abaci Robot <abaci@linux.alibaba.com>
> Signed-off-by: Jiapeng Chong <jiapeng.chong@linux.alibaba.com>
> ---
>  arch/riscv/mm/kasan_init.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index 3fc18f4..e202cdb 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -214,7 +214,7 @@ void __init kasan_init(void)
>  			break;
>
>  		kasan_populate(kasan_mem_to_shadow(start), kasan_mem_to_shadow(end));
> -	};
> +	}
>
>  	for (i = 0; i < PTRS_PER_PTE; i++)
>  		set_pte(&kasan_early_shadow_pte[i],

Looks like this one has already been fixed, thanks though!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-c78e0139-c0f9-4a61-87ab-f9658bfe5a42%40penguin.
