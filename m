Return-Path: <kasan-dev+bncBD4NDKWHQYDRBOHXS7TQKGQEG7KZS7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 727A327418
	for <lists+kasan-dev@lfdr.de>; Thu, 23 May 2019 03:47:36 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id u3sf2077164wro.2
        for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 18:47:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558576056; cv=pass;
        d=google.com; s=arc-20160816;
        b=ECqMdkXZFNi3U4rlcWeBS+MYxgXEI43pZIo3GCKtw+7xQ1JZjXNlGigjSIh4OPNPIp
         qWdrPFH1SWVgSKXK4lxa4UN1sAb1Bx6YRaNSvVEtdMt+n8tq2O0tRqcHschAAWnJjg/o
         aAeyEooHOC1DY7RoYyDWDCC05A64bJeebiM4bqzZOO6vfUjd2qzkYNk9YJqJvYzybNWg
         VtKWm4c5wJkLMpf5XwFaAST9WBJFsnVeBXTB8tFx5iImndVRQOBby5mC1TI0++Mkln+T
         VNBIyVT/SU8EfY15fq5uDTp5L1lIFygTR2sD3ZmOYSof2siJy0bge/xCwVQO7vMFObG/
         C19w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature:dkim-signature;
        bh=3MpaHLEy8EcPEfnL2hFEMKVeKVGxhU41b4JtrZShIRQ=;
        b=bi+SF01Cmdoa3Hd8m6UV46FDsNpwEdnmYiQLsv+kSbQx+VstQz1iuKBNcWfYKhdxHr
         8z16RHzJPwhsEs39ixai4ycPhm6ggouA7PmRGe0uFS5fshKobxQN6AxbTerHeVPFCcxp
         AgAw+skDGc6ldEGYEyE+VjFINMTp/VbWDw6hImilohVTez6qU8UnfJMdyfJt69klyTRv
         cUnOd6c5VppT8PgsFZPF0uRO+wzKAAVku80XqcFQ8NTkIW3rtkpLXf02gcGh7NZ6S159
         QmEwd4nOSTcvr72Dt/hmi8SImnS9W/pNQIFY5Iu3ZXt1aQCVk2scloNw+Can3ZSeHivV
         TKWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=RAHsstRp;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2a00:1450:4864:20::543 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3MpaHLEy8EcPEfnL2hFEMKVeKVGxhU41b4JtrZShIRQ=;
        b=Z4MQ37DsHhT1pydX6y56CWPlpjniTmEBhwRMwLoE/2LmBV5qJIIIgy1ENpHc+GfLF+
         +scgtnyL5fV6PzaR5GONG6KZRGpjyg2VqDnSlJSBujJrBozvK4hle9VA4C/cYg26f5ZU
         bEyHA1gCzvlSvNejGhZoDoMXRmzwz0NpGKdvlU5LQ+r/UA/mASd1hh5qKdekMc31eNMA
         kFQMuO5YsYY5y/MaR7DntYfzrh8s00UdzHB8KbL2qc0F6vep5hlZ+W+8KWqNV7k1Kj4U
         w0Hy2Jy0cOHk/NlTTmUixFadJ+4aTRtuq0MmidsbziRPRoaezf5TnoALapjfIB7p6nZ0
         hL3Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3MpaHLEy8EcPEfnL2hFEMKVeKVGxhU41b4JtrZShIRQ=;
        b=Gvejrqul7k6mNmGyoGNSoQ+sb4BBu3mRfgX5j9osiPubXzkeMg7dV85p+KX4teGrzO
         kstZiSS31X/tyNC1N334R8AXXBXCGcMu9VCvKec+LZtEYquBlxEUsLWWpYlLh0Wbw78z
         KvbYEy/msRURJgcWOrZx+D5RbvtmyPTWEYNm0Edw9ldgn7i29MGQXX/cpvxKRJFV9bAc
         nzUg6DY7ejTW9shlYJtmwKOyLiGfulP4Yl6TOxLyYMcGRhSTeMQKejMqaXaAFABtMi/v
         FVQ6ntKeyvPyHLUFRVD8ZoVW3MCiJ04QmTGvcivLDlaLysilYuHIR6Qyrx9fOEw3ozs3
         wflA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3MpaHLEy8EcPEfnL2hFEMKVeKVGxhU41b4JtrZShIRQ=;
        b=PifWbCbByPqPcqJd6BAeZngtu8kD1FU5hNrANYmsOPfuOJxESS0LXErH83U5dqtVxE
         n279DV7pLAi1P7SmrdN4ItxUiuLGaGKTgkxpujaCOKx+c2kQy9v1U+biU6yI9jorwz+u
         t2h6rX7T7DRGqc2DyD7OdPMOWXELElhXauTC4PJZqNcqowwMPZSHW90HgM5oMlqjgdES
         o8iI7krg2eMRrYECutzN6zTZo5zHLZEDXNSEgWe69VVjUKW6NTV+0cgW2FHHV0/OWy1K
         YpRtji4KPpasuQlQvHIRdBSwZYOcZe7IzjmX2BDEPLBGzgrAnCrI7wxPCr3Gf/H6IIIr
         kQ2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVIeO5TqLvHO6f+Uyo+YQirIh9HnkQz47mRl41Qb1CdViZnnWru
	rLqbzLZixLrZfrSZnF0WDgk=
X-Google-Smtp-Source: APXvYqzp+tJkmh/JRLmlPflGjGk+SlesE1WZHLKOjA3ynawSNzL3GHJoIRltpV1HIVGqUrHESmSfkw==
X-Received: by 2002:a1c:f910:: with SMTP id x16mr10197192wmh.132.1558576056160;
        Wed, 22 May 2019 18:47:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:82d2:: with SMTP id 76ls928461wrc.1.gmail; Wed, 22 May
 2019 18:47:35 -0700 (PDT)
X-Received: by 2002:adf:f9c3:: with SMTP id w3mr10291886wrr.271.1558576055794;
        Wed, 22 May 2019 18:47:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558576055; cv=none;
        d=google.com; s=arc-20160816;
        b=yHCvT6jggb1pYZgYvnuIfxDQJqbtrUrazAn5WrrP4v2Rb1Youvt7Ni8P+HlwecqDmf
         EjEXcxtI4vdawF5N9b4uPhAk6L70S/sjUeC+nZSyKV6dApNhrxxk6HpC1ZjeYPD5D45h
         SHXvMwzqFcP6nGtpnO6ROp5tkiM+yFExzV+HNx+dULx1pl767SXavHu6P9DN9EKnfI6y
         lHQgAWP8wPgb8oXJLjXIk2rSVuzKcNTZvcJHK8U0DAv17t0x8K8HXeVYwrsiGyXsEXVW
         j3Ir31wqBY9w4jiUI7u4vpcKNyeAHdPxN/ZXzJZ24qd1hdEXerk1BC4OC493Q9FqycaU
         XjWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=GhDOpD+a8hZjtMNIICSVb0siagk1dgNYZl1xyc8Nh/s=;
        b=ZK+NCLJ5S2NLjs/AE+R/xca94EpvFsWOGCs1alMavLNF5tVy2ni/L3aYkPvub9Cy5q
         1Bv8oEopx9DvjVSmF5SC4XxZe0IDJyYoI2eDcmJkVVm71Ixv1rIMZk06Y4VspbYmZ3m1
         SqjKkJ6/ko0r6U5LT8LM+0TbU+s/FlnojJUO5ZCmMuhQajlWYhHveQ/KN3caN/OeX3jO
         pvn1L4jru6jQlxR6GtSxeKe7ltC6rwO8RwlUOnU/lcW8UaLyD75auDQ9L28zGsrvux5p
         d6c5bMEcF49V/q2USr33N36/jKQpsIvLNfgmXUVtaYnd9kwUDk7ecNEMGbHMMdBzTxWH
         4Rew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=RAHsstRp;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2a00:1450:4864:20::543 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x543.google.com (mail-ed1-x543.google.com. [2a00:1450:4864:20::543])
        by gmr-mx.google.com with ESMTPS id h5si2401761wrc.1.2019.05.22.18.47.35
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 May 2019 18:47:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of natechancellor@gmail.com designates 2a00:1450:4864:20::543 as permitted sender) client-ip=2a00:1450:4864:20::543;
Received: by mail-ed1-x543.google.com with SMTP id m4so6647574edd.8;
        Wed, 22 May 2019 18:47:35 -0700 (PDT)
X-Received: by 2002:a17:906:488e:: with SMTP id v14mr33945656ejq.216.1558576055392;
        Wed, 22 May 2019 18:47:35 -0700 (PDT)
Received: from archlinux-epyc ([2a01:4f9:2b:2b15::2])
        by smtp.gmail.com with ESMTPSA id x22sm7584539edd.59.2019.05.22.18.47.34
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Wed, 22 May 2019 18:47:34 -0700 (PDT)
Date: Wed, 22 May 2019 18:47:32 -0700
From: Nathan Chancellor <natechancellor@gmail.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	clang-built-linux@googlegroups.com
Subject: Re: [PATCH v2] kasan: Initialize tag to 0xff in __kasan_kmalloc
Message-ID: <20190523014732.GA17640@archlinux-epyc>
References: <20190502153538.2326-1-natechancellor@gmail.com>
 <20190502163057.6603-1-natechancellor@gmail.com>
 <CAAeHK+wzuSKhTE6hjph1SXCUwH8TEd1C+J0cAQN=pRvKw+Wh_w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+wzuSKhTE6hjph1SXCUwH8TEd1C+J0cAQN=pRvKw+Wh_w@mail.gmail.com>
User-Agent: Mutt/1.11.4 (2019-03-13)
X-Original-Sender: natechancellor@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=RAHsstRp;       spf=pass
 (google.com: domain of natechancellor@gmail.com designates
 2a00:1450:4864:20::543 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, May 02, 2019 at 06:40:52PM +0200, Andrey Konovalov wrote:
> On Thu, May 2, 2019 at 6:31 PM Nathan Chancellor
> <natechancellor@gmail.com> wrote:
> >
> > When building with -Wuninitialized and CONFIG_KASAN_SW_TAGS unset, Clang
> > warns:
> >
> > mm/kasan/common.c:484:40: warning: variable 'tag' is uninitialized when
> > used here [-Wuninitialized]
> >         kasan_unpoison_shadow(set_tag(object, tag), size);
> >                                               ^~~
> >
> > set_tag ignores tag in this configuration but clang doesn't realize it
> > at this point in its pipeline, as it points to arch_kasan_set_tag as
> > being the point where it is used, which will later be expanded to
> > (void *)(object) without a use of tag. Initialize tag to 0xff, as it
> > removes this warning and doesn't change the meaning of the code.
> >
> > Link: https://github.com/ClangBuiltLinux/linux/issues/465
> > Signed-off-by: Nathan Chancellor <natechancellor@gmail.com>
> 
> Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
> 
> Thanks!
> 

Thanks Andrey! Did anyone else have any other comments or can this be
picked up?

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190523014732.GA17640%40archlinux-epyc.
For more options, visit https://groups.google.com/d/optout.
