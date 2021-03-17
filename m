Return-Path: <kasan-dev+bncBCRKNY4WZECBBF4YY2BAMGQECHTPFZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 7135833E89C
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Mar 2021 05:56:56 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id t23sf18816078oou.5
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 21:56:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615957015; cv=pass;
        d=google.com; s=arc-20160816;
        b=AXL3kCuJ4iPNNhilt1PU6rykwfG1kl6EPMsbQFd8xGX++J6i/mdKQyU53zb4F7akfx
         Atf3T2aC4qUPT5Av06c+oe0/0yWuH5r0WZZnq9endW4wKZtkio5xH6t8BDcU1UTJ+uFY
         xtWWTHN2FbaAElc4a6+q8L+icPFJfXywGbIxHp7lbGyVtw8GDAtlUuTRwBWf0xws9G4j
         P9XEbFXuElRaQ4slnMV289k4XIHGc+bWbSVSKR6es3A2znidG33AYNnIHpMYyOhNXdfH
         s4zQBu0jynP7jeweEVit6vo9AUQudeFYm6d9JnI9apjczcfPxERGpKwi7vSH13smbKWI
         b4uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=XsYDD+3DduMrVrOB5gwkhTtrkMoMWyqzbi9N6+065pU=;
        b=Sl1hSGAUTuFFHg5W/htNLYm2l26r4U1ajGeiG9naD9Sq8K0/gP+r9bD1TrOHoT5Ewf
         BOCYOXdCJQUrQsl/R/Ieas9fkrRaQun2YUm+ayEvCvQR6CI2//8FArDrtKUSdfSAyk9J
         pAK98ROTtfE1wVR5elRt8IVAkO8ChJQ64XtbwVcW8tVF5zb8ogN/Wgw1nlfGEtwLiY2i
         ugcvoxmp6oNzoKuTIPWzGduf4sbR6/bnM7/eFFJRwWBsjAq8Rr58ZYFjxG9dvGy+PXmS
         yxno2qQVReOPlXfAf2uO8G+YB3xPulxL1Z4fLyJawioUm2potIidsG897CXD3mF21e/a
         Yd/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=rkmJjRKS;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XsYDD+3DduMrVrOB5gwkhTtrkMoMWyqzbi9N6+065pU=;
        b=pKUAYnZxYi6a+oHczNTZD9muXAUyFi3TtdrgunXbYPSeXEs3RoRQSgBBy8TmIXOaBu
         ItjVw34dMOPVJ1xoce7moYNCx+zkNXpeIxsV3BHQbufuRtPuEhtt/xCRbXYNoj5K0ADv
         XfNXc10YEj6mHrISxXpZneJ9zOz/JERa9I/sRGZQPUAmJAruMIrM1nzYH2WgkJT2FT34
         rNnPtLe2rl0whxSOc+4QHLrYX0rJ3SLsg9LeMp+jvkFsdy5rlPhzeUX+OXhEWp5d+yPq
         yKFCYmRry9IPAR1Jy8LNyf2nqu0YRczROQN6ddvzLynClRGA8MTiS5j1Sg6TUxPmmxrV
         mskw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XsYDD+3DduMrVrOB5gwkhTtrkMoMWyqzbi9N6+065pU=;
        b=k/dsknxM1AfVnyayS90Q7E5n8sxPfcRJbp4wCL52Or7YrCe+8MhC1Z6qG/3vd9DT/M
         hzf5FECpAxCSkqYbs9t6X+P3Vo7osQ4Dbtm87YWlYTaMkq6NXOhIeLQ53ZTv4vDam0qj
         et7STJUKb/Kp3u0OrSbX4VfQMqRLKi9hMTSS2w6t5HtZDYniSjaPA/5btZKjQDe9NGJo
         sX4FTTyVj0eNPd9I+HgFDdEX+HvyhdRXQVadkYjbd/kJbcP1CGwq2USdl4MFpjvVYxpX
         MlivYiDpeNLn2s7Gt1EFRf3SjwpPTwZ1RY74mKP74QpntDTb5d0YEQr/DXXE+J9PwJob
         IiqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533r6ESIMisuH9V44AZ4jHW1HVDq1rcP3h11drpSSxKg2ADAKqDT
	gPvcaZJ6gg1N+o2/lSvRVEA=
X-Google-Smtp-Source: ABdhPJy35M8KyjinZaD79RNdW8fqj/NaY74A0XTn/oe5ShCbdKHKetT13m1TdLLgQR0RK3qHeYPDmA==
X-Received: by 2002:a54:4413:: with SMTP id k19mr1545634oiw.72.1615957015072;
        Tue, 16 Mar 2021 21:56:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:208:: with SMTP id i8ls1486569oob.7.gmail; Tue, 16
 Mar 2021 21:56:54 -0700 (PDT)
X-Received: by 2002:a4a:45d5:: with SMTP id y204mr1803900ooa.33.1615957014730;
        Tue, 16 Mar 2021 21:56:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615957014; cv=none;
        d=google.com; s=arc-20160816;
        b=zYVRocP8mGFKkQj4jhcPKfd8ZsKqP8bq39BqLZCPAN1Pl4bIiuZkuMNTTRti4laTYS
         tKZB+/+3+svMBtUVKZKAMxNyR7jb90f2cUUGABlS22Xk2ZLA3s7RuN0PlQowxzZ0Qcg1
         5/OTt7yhlDis9QHV8ISk+YVPQHtLFdZYXFhFkLFvK/4iK0oTUASwp1UnjwCpzVMfh8en
         2paxuWa9cEx/Leyp3CMZ/2h490Eh7nSoR1Fn8kWnRhuUK37OoDx6mnMN0An94wBH/P5/
         +ofgwXbfeL22PJJKdtAI1af79enqKlMk/Cqzzyit98ewCDuFA89ijJdJzfFLa38JEE21
         gPeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=kNYiVBd1cBCop/nrtBQYXoofnHMlkqLGb5kuKDRfR4g=;
        b=eX9eQbMsxJvktaXaAqXtLet+1WT5K9aqvZNPTLvFtA2b4J1OrL08fTtuKiSBWCvmVP
         3RVF3s52F8334z/eA5tR5y8LLU5zkNOqhwhVB9yDDtc7QzvxjjlCy64m0lNJNwCJgIVK
         8+hneMLU7k/FYI8dp+uF4RlSPPOObt9OmTvca6zqXlpDTy25ApFIbNxCsl1WwaSSZjVs
         70LmSQ0nREXcKYyX6+NkyewuxRKt582TGvrfUzFGfitwlePxMeOkpimML/OcQLRXQmLH
         3EqhdK0CBNvZOHbm2bupeASdb9hUqd9LaILUQgPJ/CgrMS8MD0cvtF60pz6TtOvAkhlL
         ImGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=rkmJjRKS;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id w4si717536oiv.4.2021.03.16.21.56.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Mar 2021 21:56:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id a22-20020a17090aa516b02900c1215e9b33so2532750pjq.5
        for <kasan-dev@googlegroups.com>; Tue, 16 Mar 2021 21:56:54 -0700 (PDT)
X-Received: by 2002:a17:90a:5d10:: with SMTP id s16mr2589245pji.126.1615957013965;
        Tue, 16 Mar 2021 21:56:53 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id k63sm19238522pfd.48.2021.03.16.21.56.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Mar 2021 21:56:53 -0700 (PDT)
Date: Tue, 16 Mar 2021 21:56:53 -0700 (PDT)
Subject: Re: [PATCH v3 1/2] riscv: Ensure page table writes are flushed when initializing KASAN vmalloc
In-Reply-To: <20210313084505.16132-2-alex@ghiti.fr>
CC: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  nylon7@andestech.com, nickhu@andestech.com, aryabinin@virtuozzo.com, glider@google.com,
  dvyukov@google.com, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com, alex@ghiti.fr
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alex@ghiti.fr
Message-ID: <mhng-8c8d3e1d-7d6a-4e28-8c18-901af08a29d3@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=rkmJjRKS;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Sat, 13 Mar 2021 00:45:04 PST (-0800), alex@ghiti.fr wrote:
> Make sure that writes to kernel page table during KASAN vmalloc
> initialization are made visible by adding a sfence.vma.
>
> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
> Reviewed-by: Palmer Dabbelt <palmerdabbelt@google.com>
> ---
>  arch/riscv/mm/kasan_init.c | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index 1b968855d389..57bf4ae09361 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -187,6 +187,8 @@ void __init kasan_shallow_populate(void *start, void *end)
>  		}
>  		vaddr += PAGE_SIZE;
>  	}
> +
> +	local_flush_tlb_all();
>  }
>
>  void __init kasan_init(void)

Thanks, this is on fixes.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-8c8d3e1d-7d6a-4e28-8c18-901af08a29d3%40palmerdabbelt-glaptop.
