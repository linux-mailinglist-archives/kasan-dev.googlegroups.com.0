Return-Path: <kasan-dev+bncBD7LZ45K3ECBBNVD32OQMGQE6Y7MXJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id B185465F9F7
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Jan 2023 04:12:55 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id f17-20020ac25091000000b004b565e69540sf106357lfm.12
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Jan 2023 19:12:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672974775; cv=pass;
        d=google.com; s=arc-20160816;
        b=R+Zha7DptRED+NycNKCZWDOJ02LLMGf2jtveLtEY+9/2vGWsdP+48Yp7jDUIIvSm2k
         XlfI4pj2dmuu8MFnQsDB5IgPpu02fGaq94F05ZDYLzb2eZtKy6nVqyiqovedYWSCh6/0
         9EqFpdUVSzGlJkf8k9wdNR4UQZjLuHtmwjhOMiA7nVMRMacqBWuVIMeEh/rA/JXui+0K
         3JQItUlGklx1JSeVxtcs0TZ7fqH6mdMz8+6f+cPHfOY3RUd1cP4XBLAxCM5rEl5jwqRi
         +7ZK4jk+GBr0CfeicCqemyAMqdiODRKgt7Wz3cbdHIkKSxXJtmzMRijZNWIe8vL7HaL4
         d0Tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=EEemSJ+DnnFZ3QOyFZv4leEdPIul9Jm5MOLNLPGmtVg=;
        b=r+WoEwJmhrKA3f/a29ZTvJiDJcvcZAoKo6/vLu97U4iqVFgRcJyDilUc11xlpSuoM/
         i9Pth/ANjTQgmbHZLKIjofdU5ZP9fNYnVxvtE/5REM9pcLQ59FfAgKggIdOcgfzYL3Ay
         HRXur9PTGlizPdR2cJI9WtdmN7lqxqRoQi4WEvrW1snaN8h9z4RCvJmf1xTVBPDNhVzn
         TGoHQZmjFOy7Mot9Qu+lnxts+Ueit0T0gOY+qK5aFwdAEHNV8Mk1hAOJ7pRAX0VQV+sM
         Jxd8s1WcUq5MZH9euazE16OOr2MCfy+EJMu+105niI3E3xvK84FuMlVJ2nGRF6L25D3P
         FQaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=aZ44bH1s;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=EEemSJ+DnnFZ3QOyFZv4leEdPIul9Jm5MOLNLPGmtVg=;
        b=bPsUdLKRHISFoVqc2Kr8p50F9SzuW2I9fZ5dEiZly6NRSwETfJF0OAm6bCLUxrQD3r
         j1NfDp8wDneZ2UauwQVZ66TzZdHJWXCmGllUX2l+1XXTO1b+g9hIssChc/XQjnd9YDSz
         Uv4fgOwiOnYhC6ugOOA6N6ajVZ2Gp57jBGf3rn0oLF0J1O/dPIJpRayrYlpgj9KlA9sf
         oEeyHtHY9oFZXYGK2reTkwzRYL3M4W/ODAp+ngcMFMtGnkn8TR5xCMhp71XWBlmVbDTd
         sP5R42uYVFkANIRVshc7ZFWXgiKF90I2/vMzHN1ujOOj2dyAkun//NgXHkH0ErXB2oqD
         GYNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EEemSJ+DnnFZ3QOyFZv4leEdPIul9Jm5MOLNLPGmtVg=;
        b=jSup/staXfqJNRBktirVJTxsaTRz/2QjOuxr9fXCpnT/rNAQauhyUASkEat8ppiGfi
         HM7PjMwyN18Hl48ToMNKDoIu2+F3BGIoJakg6L2uk9pDrEKjNC1Akw+53mzEexwg0byS
         +BaLCojrtbQpqw7FEE1HRXOXmUkJWrhrt2LPDA5hoPX90MTyI6a8MrxgFOn1rBqqnHwR
         8+NtxiOEEoMc09BR8s4CnMWaVLI70fO+Voh8OfvhKFCm8XEIlpD1uNq7S8Lf1b67zPmn
         zlCk5qymC+hBYOGEiCKPmDbyrxS1fpJuR7Ft6Zq7xNO+RRDRcAd/xa5Vl/OBA+7yVC5N
         eVZA==
X-Gm-Message-State: AFqh2kpCgFXKuTnCUhu0uLwJlqCG8J+pnzeeUTjB2h/xxtCgHg/eD/Jq
	ZA3kSrGbksBmI9w0MxBCd4o=
X-Google-Smtp-Source: AMrXdXvvjum3DKoQ+1Jv2Ib4a6GO73ElWcYQwwKBOGUdSHKSxjvgcBVzBr+NO4u/qtoDhcM4kSb4VQ==
X-Received: by 2002:a2e:864f:0:b0:27f:c1cf:e4cd with SMTP id i15-20020a2e864f000000b0027fc1cfe4cdmr1848998ljj.62.1672974774903;
        Thu, 05 Jan 2023 19:12:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:5d5:b0:4a2:3951:eac8 with SMTP id
 o21-20020a05651205d500b004a23951eac8ls3884980lfo.0.-pod-prod-gmail; Thu, 05
 Jan 2023 19:12:52 -0800 (PST)
X-Received: by 2002:a05:6512:39d6:b0:4cc:586b:183b with SMTP id k22-20020a05651239d600b004cc586b183bmr1584793lfu.60.1672974772918;
        Thu, 05 Jan 2023 19:12:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672974772; cv=none;
        d=google.com; s=arc-20160816;
        b=freKT+r+wCM5+yUxsg7ILIY0+BJtZdRcUC+jcx1osmRPfZgCBRrAMO9zjPk1cfqEIM
         zVEb9qGKM/Nj7lsU/urwl4UX678XxyMdq63ECbl+hGOF7ussGMmcZsqvQvXzWmX2ncYA
         jBHeRBMkm9PxVUSOvthSBON8fcfWxqtTbfVSM+QHRrzUct57tqRZz8xUL2toDiQIRMEE
         1pWITK+YY2qPZfqj7Kr3YeqD5Tkk0vLrdQqwR97lG8TB0mg3+YuG1OBWoHNLPXW50LhU
         7vd9A2Z8XS8LXlaNNJrNG5mUcNd9g2be4uC9elgH/U8FerhF/ocrB0VvKoChZtlLalrx
         bkbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=21zf54EYWZhDQm73m3HRBf5o2in9eTbBIqduSXeMgk8=;
        b=UUFg6dhs2oPcFcbBwTJia+1rTnslasaYgdJYqO6K/tk57zG7de0e6ZfPNBAjEfkVVi
         Il3aIsbBukT05dNd5SRH9sR5T9ZgaZFNdr3I16JxWT2j8+KEtcGRmB1wyNyCWaRxcs8X
         RELB3Doj1DRUSRATC9AhAKOp5fepof8GqCIJutNg71la2AI/8pl4zM0+b3SWwiBg7Cq8
         TzN316e/lgdi34OBaJIWG4jAknvKZfRY8N9gJIw21YmwPl1dL5ccfcgpOCJ2vY2Rp5YX
         +oWZ21QcgdqW8ovjawWji0faY6vSu+r9HTI4w6ENgv2uICLUVKij3QdBe2LyNYjGAc/+
         O1Cw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=aZ44bH1s;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id o1-20020ac25e21000000b004cc5f447477si72806lfg.13.2023.01.05.19.12.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Jan 2023 19:12:52 -0800 (PST)
Received-SPF: pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id ja17so265083wmb.3
        for <kasan-dev@googlegroups.com>; Thu, 05 Jan 2023 19:12:52 -0800 (PST)
X-Received: by 2002:a05:600c:3ca2:b0:3d9:da3a:ef9b with SMTP id bg34-20020a05600c3ca200b003d9da3aef9bmr639110wmb.31.1672974772270;
        Thu, 05 Jan 2023 19:12:52 -0800 (PST)
Received: from gmail.com (1F2EF380.nat.pool.telekom.hu. [31.46.243.128])
        by smtp.gmail.com with ESMTPSA id p1-20020a05600c204100b003d99a39b846sm65434wmg.5.2023.01.05.19.12.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Jan 2023 19:12:51 -0800 (PST)
Sender: Ingo Molnar <mingo.kernel.org@gmail.com>
Date: Fri, 6 Jan 2023 04:12:49 +0100
From: Ingo Molnar <mingo@kernel.org>
To: Aaron Thompson <dev@aaront.org>
Cc: Mike Rapoport <rppt@kernel.org>, linux-mm@kvack.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andy@infradead.org>,
	Ard Biesheuvel <ardb@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Darren Hart <dvhart@infradead.org>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>,
	Marco Elver <elver@google.com>,
	Thomas Gleixner <tglx@linutronix.de>, kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org, linux-kernel@vger.kernel.org,
	platform-driver-x86@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH v2 1/1] mm: Always release pages to the buddy allocator
 in memblock_free_late().
Message-ID: <Y7eRsWuu8jZgZtUt@gmail.com>
References: <010101857bbc3a41-173240b3-9064-42ef-93f3-482081126ec2-000000@us-west-2.amazonses.com>
 <20230105041650.1485-1-dev@aaront.org>
 <010001858025fc22-e619988e-c0a5-4545-bd93-783890b9ad14-000000@email.amazonses.com>
 <Y7aq7fzKZ/EdLVp3@gmail.com>
 <0101018584d0b5a3-ea0e4d67-b00f-4254-8e1c-767fcafbec31-000000@us-west-2.amazonses.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0101018584d0b5a3-ea0e4d67-b00f-4254-8e1c-767fcafbec31-000000@us-west-2.amazonses.com>
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=aZ44bH1s;       spf=pass
 (google.com: domain of mingo.kernel.org@gmail.com designates
 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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


* Aaron Thompson <dev@aaront.org> wrote:

> 
> On 2023-01-05 02:48, Ingo Molnar wrote:
> > * Aaron Thompson <dev@aaront.org> wrote:
> > 
> > > For example, on an Amazon EC2 t3.micro VM (1 GB) booting via EFI:
> > > 
> > > v6.2-rc2:
> > >   # grep -E 'Node|spanned|present|managed' /proc/zoneinfo
> > >   Node 0, zone      DMA
> > >           spanned  4095
> > >           present  3999
> > >           managed  3840
> > >   Node 0, zone    DMA32
> > >           spanned  246652
> > >           present  245868
> > >           managed  178867
> > > 
> > > v6.2-rc2 + patch:
> > >   # grep -E 'Node|spanned|present|managed' /proc/zoneinfo
> > >   Node 0, zone      DMA
> > >           spanned  4095
> > >           present  3999
> > >           managed  3840
> > >   Node 0, zone    DMA32
> > >           spanned  246652
> > >           present  245868
> > >           managed  222816   # +43,949 pages
> > 
> > [ Note the annotation I added to the output - might be useful in the
> > changelog too. ]
> > 
> > So this patch adds around +17% of RAM to this 1 GB virtual system? That
> > looks rather significant ...
> > 
> > Thanks,
> > 
> > 	Ingo
> 
> It is significant, but I wouldn't describe it as being added. I would say
> that the system is currently losing 17% of RAM due to a bug, and this patch
> fixes that bug.

To the end-user gaining +17% [or +3%] extra usable RAM compared to what 
they had before is what matters, and it's a big deal. :-)

Thanks,

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y7eRsWuu8jZgZtUt%40gmail.com.
