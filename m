Return-Path: <kasan-dev+bncBCRKNY4WZECBBXOT7CMQMGQE4LF4KGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id F04BB5F5E27
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 03:05:34 +0200 (CEST)
Received: by mail-vs1-xe3b.google.com with SMTP id m186-20020a6726c3000000b0039b2e2e040dsf100956vsm.9
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Oct 2022 18:05:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665018333; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xspiyp4n5ogjuTaOwAfCMB/JvoQ1IPeAdlv8MW5NMjW2fY1WJx3geZqf114HyPqnk0
         st3TBlPHurgVvJTb8xhb8zW2IGK+O4D5XTOfgGYgDtViUzNNRHKTqPyDSQVFxRBQdEr1
         87T114LbuHZAbetsXafvvWkOZpgMKyKVoI9hHbDkv18jlJ6KRWMCcp5kawKBk3oPUpRj
         fhcDe9TeXAvHEP3eDno13h1i+7bda0whVtgAt3bf99+hqdbFikPt1PbVoAmevCUwE+EC
         7U3ITpa4/G7ahMj7z+gxMj+CZ35Iu5FmwKH1XLj/cWn9vURTUqRjXfFeDAxzpu53rgk+
         coAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=wchRuLWfFXRbeUlQjemc8ns+KKHHELKO0g9RkE+Cc70=;
        b=PdMl6dhtjo4K6FFVGnC/L2PP3Mp3h6KXg8MdfgHNnPrgSxFK4nqPfCqgm6UL5g3++u
         42OAl9bkC5EHnCh3Ai0E5g7gypMzeh+GEKFXRqpQJ0DS+6rPpvYZjWKUOJabtrjy0jOa
         YRu1oke4iLmcW7pciSbskq8QAQWYiU2rFkOlIMhuBHT9EAjT8jtywbSwIN/uv87MfEdz
         3YTEN9wCyQHfSCSEW5YvDIxqBuKJlkBJvLEK7n2EGBlvccENXVEJxFZCX11t5dnLyKm0
         RNm2VwF4Mt4sIsUxKAYo1J3/1rWa0qH3ep9oYiLEsSgve7J2ZDYT7pBKetu3V8uCiP0Q
         LaZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=W9oFKSvS;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:to:from:cc:in-reply-to
         :subject:date:sender:from:to:cc:subject:date;
        bh=wchRuLWfFXRbeUlQjemc8ns+KKHHELKO0g9RkE+Cc70=;
        b=kbm7KzIDQRBvVrZiy7RfO1EKfMOzcj0YhH6HDcpkl2yjsLqqTvdpKrxNPxTycTfnac
         vQaQDJDnIpDqao4HHRfB7LEyUXYhHsLPtcSceOmKsno2ayV9yQLGAYE54MavdPBuLphS
         Jk12Bl+Q5UtOkfn0SS5EJTvpWhOU5WoLeYOagSIrswQsLHYKYHPQYw2gGoD8lbJPw+4a
         7OQVjr77qRDd1eYyjPpocHAaEoFViNGWa6WV3AJIntPTu4NU2V2cUIP9RCjiIVTEJekp
         86TyijKRXLO/occKSA/+5UWYulDQAHw4XEGxfloR2kJAfY0bvi52XGMVFgkhwxzspOhD
         WrQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:to:from:cc:in-reply-to:subject:date:x-gm-message-state
         :sender:from:to:cc:subject:date;
        bh=wchRuLWfFXRbeUlQjemc8ns+KKHHELKO0g9RkE+Cc70=;
        b=USuyWyy3TPpHzDNBlat0ueIW4fgTFXJ8uyGq30y3miKvbiax2+m4K86AvVZj7cUJ6z
         E60LOvJca3Z5WWlhhPHq2wILecwMyphq8gWkxHCx8UJUBpbWmUZ5dpGm9iHvtDTQz8fw
         UQ+m8AvjFn6kChoGpMTBPIuyUxQT82Ik6Vwz42Y/LFe9leV4EEBQTfaZqdixWYVBAtw9
         1kXFG+VdcFStgZy6PF1S28aosV+vxwROdsqsVFsLQKLCSsnCTSPEAd4/z7D6KxGIe6mE
         Kbr7FUx2+HA8UYbGmsUYM87Ugz+06l7hsARz4tjZzfQ+tvdVVqhVzjiYmw6nMEB6cYd8
         27sA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0Av/aaPJVvBlqBUagEQNCCXyneiYHlQt40pC+Zj1LzVQSfp1N/
	eoRZ46EhhybFvfXmFF9eCFc=
X-Google-Smtp-Source: AMsMyM4KRx5QtVYVvF7oiJVbC7pmZX97Gqtuf+0eW5LbRW/s6kbxNQ96JzVX6CqYMFx1mhRzepPcEQ==
X-Received: by 2002:a1f:a196:0:b0:3a9:ae17:9563 with SMTP id k144-20020a1fa196000000b003a9ae179563mr1070319vke.22.1665018333420;
        Wed, 05 Oct 2022 18:05:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:dd19:0:b0:398:a64d:75a7 with SMTP id y25-20020a67dd19000000b00398a64d75a7ls93997vsj.0.-pod-prod-gmail;
 Wed, 05 Oct 2022 18:05:32 -0700 (PDT)
X-Received: by 2002:a67:ed07:0:b0:3a6:5bf7:8ba1 with SMTP id l7-20020a67ed07000000b003a65bf78ba1mr1342925vsp.62.1665018332720;
        Wed, 05 Oct 2022 18:05:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665018332; cv=none;
        d=google.com; s=arc-20160816;
        b=MRt4K4Zv83fy60vP9Cd1J3pnRugII2XWJFRaN6U8hdXQwLnN/XZTMIiXfTELp3fkDr
         fPvCqXJL00u+Jfhq3ug+usKfXwiET+REijh66tNV1p4zAJaoFW1XsdNWKsLUC8ExZUam
         D4y31f7sF9zNYIdAuzPWhJW0kHOQYHcX4VXcbGnqjdsojhqcPBBeA+ZYhlN+fMjrdMWH
         lbxxPcxr5bw2Ou2MAhODpEo8qNdzMPXc5CDLncCdV7y1/mk+sR4WTvaRwcA61D0PfH1v
         74XqYw7+8C0v7AaNbHVXW3a3Ml+6lFg8kM/rGkIaw4nfXr8PF5DBU+age3x0o4jYf4SM
         +YwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=6zz+HXUH9nJdRQI27LUzdzL5vjVdFK5hIVfPKFeeoWM=;
        b=d4A0gExdBIN7V9NyNzq1EAg98/C+jQlUn/uBcTQXzr523oDJvPyluRBDugfVHkoi9V
         Y6773V2qQfU7e01oLkZLlCPYDSsYNr81xlmoZJKeLTFFXB3ovQtcQVC7qCqzzOLM+dKb
         DQxXQg+WdscOo3bJbjKXgIPae1INZd1okoxWi3QRycmJpCSh6LAVwYcDZGmyXDL+15XH
         iiNZSLMsjXUas6y6wlgQmWkZdnnTUTOjMksP2AhD54Gh9jeOvkh4Ud1+7wBCJAPTkcwx
         SNKg2ygJ8+glH+yjl88qQzcffy3yiaBroYH9kN7KlQg/DY2DAx1wmBDxl4fLqiJunlyG
         wN9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=W9oFKSvS;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id c19-20020ab06ed3000000b003dc811b4d2asi9342uav.0.2022.10.05.18.05.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Oct 2022 18:05:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id i6so677279pfb.2
        for <kasan-dev@googlegroups.com>; Wed, 05 Oct 2022 18:05:32 -0700 (PDT)
X-Received: by 2002:a05:6a00:a01:b0:561:7e74:11b3 with SMTP id p1-20020a056a000a0100b005617e7411b3mr2084194pfh.35.1665018331640;
        Wed, 05 Oct 2022 18:05:31 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id e2-20020a17090301c200b00172ea8ff334sm11129483plh.7.2022.10.05.18.05.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Oct 2022 18:05:28 -0700 (PDT)
Date: Wed, 05 Oct 2022 18:05:28 -0700 (PDT)
Subject: Re: [PATCH v6 RESEND 0/2] use static key to optimize pgtable_l4_enabled
In-Reply-To: <20220821140918.3613-1-jszhang@kernel.org>
CC: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
  vincenzo.frascino@arm.com, alexandre.ghiti@canonical.com, linux-riscv@lists.infradead.org,
  linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
From: Palmer Dabbelt <palmer@dabbelt.com>
To: jszhang@kernel.org
Message-ID: <mhng-30c89107-c103-4363-b4af-7778d9512622@palmer-ri-x1c9>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112
 header.b=W9oFKSvS;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Sun, 21 Aug 2022 07:09:16 PDT (-0700), jszhang@kernel.org wrote:
> The pgtable_l4|[l5]_enabled check sits at hot code path, performance
> is impacted a lot. Since pgtable_l4|[l5]_enabled isn't changed after
> boot, so static key can be used to solve the performance issue[1].
>
> An unified way static key was introduced in [2], but it only targets
> riscv isa extension. We dunno whether SV48 and SV57 will be considered
> as isa extension, so the unified solution isn't used for
> pgtable_l4[l5]_enabled now.
>
> patch1 fixes a NULL pointer deference if static key is used a bit earlier.
> patch2 uses the static key to optimize pgtable_l4|[l5]_enabled.
>
> [1] http://lists.infradead.org/pipermail/linux-riscv/2021-December/011164.html
> [2] https://lore.kernel.org/linux-riscv/20220517184453.3558-1-jszhang@kernel.org/T/#t
>
> Since v5:
>  - Use DECLARE_STATIC_KEY_FALSE
>
> Since v4:
>  - rebased on v5.19-rcN
>  - collect Reviewed-by tags
>  - Fix kernel panic issue if SPARSEMEM is enabled by moving the
>    riscv_finalise_pgtable_lx() after sparse_init()
>
> Since v3:
>  - fix W=1 call to undeclared function 'static_branch_likely' error
>
> Since v2:
>  - move the W=1 warning fix to a separate patch
>  - move the unified way to use static key to a new patch series.
>
> Since v1:
>  - Add a W=1 warning fix
>  - Fix W=1 error
>  - Based on v5.18-rcN, since SV57 support is added, so convert
>    pgtable_l5_enabled as well.
>
>
> Jisheng Zhang (2):
>   riscv: move sbi_init() earlier before jump_label_init()
>   riscv: turn pgtable_l4|[l5]_enabled to static key for RV64
>
>  arch/riscv/include/asm/pgalloc.h    | 16 ++++----
>  arch/riscv/include/asm/pgtable-32.h |  3 ++
>  arch/riscv/include/asm/pgtable-64.h | 60 ++++++++++++++++++---------
>  arch/riscv/include/asm/pgtable.h    |  5 +--
>  arch/riscv/kernel/cpu.c             |  4 +-
>  arch/riscv/kernel/setup.c           |  2 +-
>  arch/riscv/mm/init.c                | 64 ++++++++++++++++++-----------
>  arch/riscv/mm/kasan_init.c          | 16 ++++----
>  8 files changed, 104 insertions(+), 66 deletions(-)

Sorry for being slow here, but it looks like this still causes some 
early boot hangs.  Specifically kasan+sparsemem is failing.  As you can 
probably see from the latency I'm still a bit buried right now so I'm 
not sure when I'll have a chance to take more of a look.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-30c89107-c103-4363-b4af-7778d9512622%40palmer-ri-x1c9.
