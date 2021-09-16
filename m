Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBNWLRWFAMGQE3LPR4EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id ABBD840DE48
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 17:41:43 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id z2-20020a626502000000b003fe1e4314d2sf5284717pfb.0
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 08:41:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631806902; cv=pass;
        d=google.com; s=arc-20160816;
        b=BpxVcBNXnuk0W+HZkqNxvrkaZ74Ay/01BPaT/2Z5gKx1rsd7SWR/OaqJMgdjSXFhSV
         UvYzFYTxaUtwpgU2hj82cKdLSM2XBUaLyur69hzlpp4PcCEbGDxYdbLgRzoEiLlg//+E
         sArG1KZdwOX+K+MIeSW941GCCuVXshOObcm9G+IQSM3cvuNZv62LL+cZb/MIJ80E8k4U
         mgvC7yVq8c8JWOFlDBX9WHRagA8KZlnKhLkTdhMXKbOhbNfHDZlMe6KwtIL7gql4JJMl
         3n+zuSAQSh2yS2SS+q1vdQH7EdFDnZGzEATsBKSqAv0lkdPxjbmf3PCfBpniyr0JyV+7
         w7Yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=H1EM/TsYcWB1Q8zzwQ49Xva7nQSiNRNVHw6FBB+K4OY=;
        b=cPwKbJLNNHzUfdVkLR8xKrqJxCNOCeZBOwhW2sl9EwZv9A0ZDhT6eNwLn+0obfVN8J
         VG4jNedgz3o8VLvgyGPmZ8ybCvmZqhc1tapiMlRQBx6LM74C2NKC+Nkdfc5ZeeZ5SE6C
         4/fZMoMuZEDDkpM8yhxLrNsJ8ye7oWhyMlIjtjaY/cKZcR7JYTH5t1uOq621rd9HHRcQ
         EC+v3lpMj7Tdam13N7rSpWu6NM45LVdlHXmlei6qBZoCMs3suSLjEyelfdvyiKc72QGM
         T35jvU5bgZJYX5H9pnVPo1WkUlIrn02TIygv+pAE9203uGV8fUwa8thVN88vzoA638Np
         LuBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=rCF98yje;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H1EM/TsYcWB1Q8zzwQ49Xva7nQSiNRNVHw6FBB+K4OY=;
        b=EsiX3JbzRjlJQfz5IKCsXWtqb/x/ibiY7jiIjQyR567Ap4K5P7K38CPJBeGaqkMK1q
         0bYznR89znSVp2WgWIJl/5DReS5ikp56bPwRqZi3+ddV99ygboX0sfgnr6bJyig9GrRD
         aryzT/hNQM6v4oOlead9RGArzMQt/CNYa1qOkP/OtYiVQfbZEURgx2WdiOa9XcPqt2fA
         c2TuWQr7SpJ2BxH0WTqTX1vfdFIO2ptm5BpY2LbIw+QN65kRizjb7QzNwKdxzdMUDE7S
         6yBMkOLBO9ZC1/SqZh0ZiLbwesBFMx0pYy3ZYx4YFMzoV4uiNNDrJ0BPBQ33P5hG8ZjS
         6pGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H1EM/TsYcWB1Q8zzwQ49Xva7nQSiNRNVHw6FBB+K4OY=;
        b=VzfiwkU2Nb4uW9LWQxAmA7it7tY7Q05C4MIfSStBGIJgTnp+WEHbDH/H609MDiwB8D
         stWnLsj86sA4NUoUeywxhxJ72IFPEIDDkg+Mc2VDJSWX0Q9MPD0OcWbPwxGnYM3rSwCm
         NgDtHGqQErLe9UxVutYlwKHKuO6cD0erbnoHeTHzrKWILhZlotBpI9x1UMNYbpNvCoWp
         a5KIeZzI6RZ9AyR7LGbDEiMZNU58aMfc8yMn3QtnR1L7iUICdFV3vRgCI23LPdSdRt0W
         CWHhnVkXBgE+rpKHF8szQUmzzdonc9k8ktaNHoezShXV+UeE8AdPhDa2bJyAjNEm8JMv
         TZTQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ZRhQcraKhXFrBRQbm9zm6/DK+66lvjcjshHKSoMtWPkr3pnQ2
	2hBxOpRaWoe4dHtG3y4cZOQ=
X-Google-Smtp-Source: ABdhPJwAVW/nKsaLdWG6reiyDrtt+TbQTp5W+fx+6HVdwMDOP+D0bWI30qajATD02ftsxwY8SYoyww==
X-Received: by 2002:a17:902:714e:b0:13c:9801:a33a with SMTP id u14-20020a170902714e00b0013c9801a33amr5293331plm.65.1631806902296;
        Thu, 16 Sep 2021 08:41:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:20cc:: with SMTP id i12ls2221876plb.8.gmail; Thu, 16
 Sep 2021 08:41:41 -0700 (PDT)
X-Received: by 2002:a17:90a:da02:: with SMTP id e2mr15710589pjv.89.1631806901773;
        Thu, 16 Sep 2021 08:41:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631806901; cv=none;
        d=google.com; s=arc-20160816;
        b=ZQkoXlCvsxLlwt1fDeaNulJDq9zt1ov9Cq4pHFxJSILrsmVOegEqeBzFcpPOciAZ9b
         SPP2WwSdILilO5f0mt/HH7L9Sr8BtEY/tTGM0V4FtaoW3xsXvIR9nM18DjSPLbr9VLns
         BtxjwDA5taORiCfrv62SzCQocwxVbwoJ8XHj7RzE3b/y9KaLSc4rU6+PcrS5LPq3dvCt
         ci4vvNj30yBhZSmvKpWjH7smuwJSRl+/hTW2u9SmnJ2HX68R/t1QCtnuNupZ/PoVumTx
         KTygffMADPCPEZBcQsAuheh/HbWQcVetNpoJm4wbR6yU2Mu+W3oF4wWZlI6ch+KGve2x
         eMJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=n3Ilu/8vnQF2QKizkVl47kk9UJvfGwMj4Qvqdqis6Hs=;
        b=GPzwNJgi/raAC9OFCzU5UPdoe+NThi5zCB6MOHSIn09N0zAN/RuaxuDSnkWh7JEsd6
         SZM2nKsJUHWdh8pwTxol2YDMv9aSBFAStxCUTZFF0kg+fAonCgkjlK0H5MW/3gslBG+C
         KfCNIM4mW1EhHXmFVBUZHrBJGBEfKWJuo7csW42dQGBCeGTEwCh2f7F5rPxxTPAWG6EO
         KmBS+cxfMNEwo34DOQE8wXvTla89+vcroVXmGdNQ45Cs7elMnH8k5fcEUHVmw30EcYoD
         qHxPvLggt3enOlJWigDfmrO8lzKX3CJazTKOniP0XSQ01AFXw8ci31H0uR808xRIhtCp
         zDIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=rCF98yje;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n63si601130pfd.3.2021.09.16.08.41.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Sep 2021 08:41:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 874CE60EE2;
	Thu, 16 Sep 2021 15:41:40 +0000 (UTC)
Date: Thu, 16 Sep 2021 17:41:38 +0200
From: Greg KH <gregkh@linuxfoundation.org>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: will@kernel.org, catalin.marinas@arm.com, ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com, dvyukov@google.com,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, elver@google.com, akpm@linux-foundation.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v4 0/3] arm64: support page mapping percpu first chunk
 allocator
Message-ID: <YUNlsgZoLG3g4Qup@kroah.com>
References: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
 <c06faf6c-3d21-04f2-6855-95c86e96cf5a@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <c06faf6c-3d21-04f2-6855-95c86e96cf5a@huawei.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=rCF98yje;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Wed, Sep 15, 2021 at 04:33:09PM +0800, Kefeng Wang wrote:
> Hi Greg and Andrew=EF=BC=8C as Catalin saids=EF=BC=8Cthe series touches d=
rivers/ and mm/
> but missing
>=20
> acks from both of you=EF=BC=8Ccould you take a look of this patchset(patc=
h1 change
> mm/vmalloc.c

What patchset?

> and patch2 changes drivers/base/arch_numa.c).

that file is not really owned by anyone it seems :(

Can you provide a link to the real patch please?

thanks,

greg k-h

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YUNlsgZoLG3g4Qup%40kroah.com.
