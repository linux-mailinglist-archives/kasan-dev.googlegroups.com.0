Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI4KRSFAMGQEJ32MNCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id D86EF40D500
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 10:49:41 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id v33-20020a634821000000b002530e4cca7bsf4468985pga.10
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 01:49:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631782180; cv=pass;
        d=google.com; s=arc-20160816;
        b=DV7C7ObewUv5pWK8Qk87/dXvEDVaQrmZ6lbHJZ9U7qbTZC7a3DsFlWhiEiOzTWBntG
         AEY/EJp+ZNtGkcwxd1NFVSQ6W9pS4O9jr1CJGmDXq/Da5dwZVEmIcTgEH7kNdUjQdnx5
         qtIcyItZsCZHxfTm27Uv/X6ddm6/RJD6JB3Wrk2f9OJP46W0eadRm8y1E1UagMFC1u15
         gj+ipJdU05/rbBF4ztCQKQY8dY+/SvibmBVLF52aAgDEBaWFcoBXvNXn7SodXOgZMgkw
         Nc/CSofgGWrkF8l7v938NQeSj+4uaB1C9hbWDY1JWcniE/LZB6r5GKALEcrT7+lnviKq
         pSBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mkQNG/r3N0E3AcPFokDJcnsaIJ2JbMga5InZ9JG3Mh0=;
        b=sQyv7UBtc6GQmH9U/t125MNYVUvR4wiPqYsgKD0fUbIvayJuSAXkA39iCMSjaYgsSU
         giZaj8VNC9RGQ9KtdIT4yyRO6nNL99eF8LbOypiqx3Z+VdFqv1nF3ToAJFWUdmCXEkDt
         sBzZn5AJz1pRUvXZDMVpOTUC0fwJHZzQBIK6+4fHarfdylDOqzdEyZq3tCMUzhL7A/27
         yd/IauSdZ6puM90fVrTZasqA/26ojxcEA3ERQ9reU0NHj90mRtpoky44kQspcgZbYEVo
         vaZaJITLihK5nnk4yJIMuoiYqd3ccdWewMGN/7uj8s3omizJT1zy31iKGH1LpFC/kIEM
         hKaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ib0a2fLD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mkQNG/r3N0E3AcPFokDJcnsaIJ2JbMga5InZ9JG3Mh0=;
        b=OgPfWguo/XqyfT/hvE4998PeiNEDkmX4m/Lepc07dOCCWFcofimiZXDeCC8L5Y159r
         LZM88P6j1mK6NHbLXbqPv7h2c/hA1wTcN1I+lPfrRDblywuTbvcECqJBWkYDVoOW+CtN
         33DDNAYm3e5NqVL8JXj5vCQ+52Kk3oPnt8jrNX1VutrX59bTI1tq6O78EOgNSDBEfsDn
         5D7lH0+f09w7AxYBp3EkjjQRUZUcN2L8vguB6jSWypHL2EDMFrbFE+E4AqibOofKVRtu
         TpLAfLpjZ2t9YgNlyODZ6bS7u9hzCF1paz9M2mGA6UB2eA+rQyu6g5Vej/U60iTiAb3/
         dCBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mkQNG/r3N0E3AcPFokDJcnsaIJ2JbMga5InZ9JG3Mh0=;
        b=cuNxpxPUtfvhRcF0bpAzok9gPFbxHaSDAhrd64H0Vmq0E5rK4mdpYxmII/Jqlf3DKp
         rXRf38VgotY7cuJ0QZV5jSJuPJjgpkMPdXapeauA8RvNzAma/bPMxn0Z84yqfe1ac6ia
         UOuiJ4RhsByXRL8fcFcx3YvGrklJ3ofiO7yvJokKuTo9XIAmpg6Q+0s8aZdo2Uq5lIqM
         Nhd1QILvt/BNDaJj8JtY3CgAOb8tTzvOnH4rFXdMBAVeJXZgoy7YTM6q9lHmgdFPKPuV
         T+sJurujRca3EqFMOsLLyuZshfq4947076ggmQo2c5sz2A5dYtLXebv4iW83y46SDkIh
         Pk6w==
X-Gm-Message-State: AOAM533s+0a4HBvoMdzA/Jw6tByj+ILrBwAAfWpTAAJoG9t/9JIZoP0Z
	qNCCqtg8n7SLbNRwwWBpeI4=
X-Google-Smtp-Source: ABdhPJzfJRqzHycMuIbQGjOc3ydsoSKDHa7GNCTsncz/R8TFsdRjICuNxfmqimqjjOxQnItho1aZkg==
X-Received: by 2002:a17:90a:bb04:: with SMTP id u4mr4745251pjr.221.1631782180008;
        Thu, 16 Sep 2021 01:49:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8b11:: with SMTP id y17ls1582514pjn.0.gmail; Thu, 16
 Sep 2021 01:49:39 -0700 (PDT)
X-Received: by 2002:a17:902:ec90:b0:13a:34f9:cfe9 with SMTP id x16-20020a170902ec9000b0013a34f9cfe9mr3719854plg.74.1631782179431;
        Thu, 16 Sep 2021 01:49:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631782179; cv=none;
        d=google.com; s=arc-20160816;
        b=kESP0LDqIk89jmjwSXkJfDJyeMIszOMEpaaA/fz09LSknUCufuZNbIVeRaHsfkn8gZ
         ZUGMT7YG06RPHXY7kLDfxI7xt25rQhmd60FxGoYk2mJ9X0ce3jMhekDYnl2p4eslOQOU
         PVKxyxtotUcQhLsqsdnLiZ6XMk1glOlposPnAcIfClBOyLQpD4PSjoxvwzVCkIQTktfH
         i74DaWxVQ0ZCfDBWYHF8JjXI86sFnXDVQOzZR9f6VsOwoAwxvxkw6uP32+E8z609gXxn
         siy56Ebb2EycO8ipf1E5b8ntejuarRspn7olQBFr+Mn9G1cEPCZaDefNw2aDINehJHdS
         b09w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vIP749jeRM51PP+EheT1+GJQiFSryXau4Nw9wt2MR9o=;
        b=rECxp4DeWdNtt/PE5euv5dn8h3+Rr9J412R+94Erj2+D6bFGiB4CMm44I4OssywGju
         F2SOEAyyx6FqkwFappuYS32IVmO29ho8vnXfEUL6cM6RjpilVFqGfRYyvDDAasCIXKCW
         /wY9KyuU8cxeL90vqq9Fe2dQTKkhFcDzyc3U+4Vj/O/XxkqxNcL/CQWusJiTiAJYYiFj
         jS4QV/B8vu0ZTHNDkEYNf61/9D4zkZ9ZG+D+sjfIymDbEtOXqPQFwlfFjLQXcb+t07yw
         6Qmg474rircGBr9v5SV0vRx1kMhEGGVd6d+JVuMoAkHw0jVBLKKhaAGGQSimu0z/UaP4
         WDhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ib0a2fLD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x332.google.com (mail-ot1-x332.google.com. [2607:f8b0:4864:20::332])
        by gmr-mx.google.com with ESMTPS id u5si546793pji.0.2021.09.16.01.49.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Sep 2021 01:49:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) client-ip=2607:f8b0:4864:20::332;
Received: by mail-ot1-x332.google.com with SMTP id 97-20020a9d006a000000b00545420bff9eso502345ota.8
        for <kasan-dev@googlegroups.com>; Thu, 16 Sep 2021 01:49:39 -0700 (PDT)
X-Received: by 2002:a9d:71db:: with SMTP id z27mr3758946otj.292.1631782178670;
 Thu, 16 Sep 2021 01:49:38 -0700 (PDT)
MIME-Version: 1.0
References: <20210421105132.3965998-1-elver@google.com> <20210421105132.3965998-3-elver@google.com>
 <6c0d5f40-5067-3a59-65fa-6977b6f70219@huawei.com> <abd74d5a-1236-4f0e-c123-a41e56e22391@huawei.com>
In-Reply-To: <abd74d5a-1236-4f0e-c123-a41e56e22391@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Sep 2021 10:49:27 +0200
Message-ID: <CANpmjNNXiuQbjMBP=5+uZRNAiduV7v067pPmAgsYzSPpR8Y2yg@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] kfence: maximize allocation wait timeout duration
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: akpm@linux-foundation.org, glider@google.com, dvyukov@google.com, 
	jannh@google.com, mark.rutland@arm.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, hdanton@sina.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ib0a2fLD;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as
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

On Thu, 16 Sept 2021 at 03:20, Kefeng Wang <wangkefeng.wang@huawei.com> wrote:
> Hi Marco,
>
> We found kfence_test will fails  on ARM64 with this patch with/without
> CONFIG_DETECT_HUNG_TASK,
>
> Any thought ?

Please share log and instructions to reproduce if possible. Also, if
possible, please share bisection log that led you to this patch.

I currently do not see how this patch would cause that, it only
increases the timeout duration.

I know that under QEMU TCG mode, there are occasionally timeouts in
the test simply due to QEMU being extremely slow or other weirdness.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNXiuQbjMBP%3D5%2BuZRNAiduV7v067pPmAgsYzSPpR8Y2yg%40mail.gmail.com.
