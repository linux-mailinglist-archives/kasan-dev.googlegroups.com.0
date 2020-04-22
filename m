Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBU7PQL2QKGQE5N43BFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 366A41B4F6A
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 23:32:05 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id f18sf1659490oov.18
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 14:32:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587591124; cv=pass;
        d=google.com; s=arc-20160816;
        b=fqu2eSyMy2lTVAtDftqK05ewvkpyhpCgVSD7nz/UtdcvqS7RHIlKaq8f9Qibk64TIg
         vH/BIR37azIKJ7Yz38fXIFTWEI40H9kVTx82S62c8AebbssgfOQrjzYjWENqLsi4T4Ox
         NEd3hB3bHnjPwF5nWvEWXnM6dtMk5DYIykrr4qSRO6R7BMKAq9R1CThjIbYZCPyZTI8W
         8YPlFC9jPVe85pWRgpF/KhAcpizFtRHdAnrXKMSiTLPd0ICC/paY42jhVzPCMGvYmkEE
         ajXSjrLdrbncvB3b3mdh/hUBegvDl3hWlVwTu/UdfZxyYTK3vK4m7tAgNbwNpipcvpAe
         Q8Dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=3zGJAhgFDwkd80ynPj6KmZxJkG/IUvyjGxtqJQjUH6Q=;
        b=OSMiOC5jqw469J/CxK3OK/NP+MTeVr5i2HlnDymHwMPPfFWgiW/ycYLbImxxBiqiae
         1Cvka4JCUVEyf9CQVjHxNz975BQAeTX344VugET8sLJFFAiwdZK5JqAp6dW0sYt0MMdc
         HmVKfugARr+oZHt8vpWGWS1XJM4Od4yKC6a05Gl3q5s5l7rIC1NkrtYVMiDB18jByBUV
         ETEuNeEf7KWiA8cMXRl4kzUux+NDOAUc5I4xJpjJE20EWe5HDkHqMPzWFTdR9WJRmTiR
         bizilhMP578xo7f3QeNQcpfzgaKlkQhHixA/E56d+QVV+trXY71LurMzUEWpOnK6lN/G
         lxzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=NdOunxgY;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3zGJAhgFDwkd80ynPj6KmZxJkG/IUvyjGxtqJQjUH6Q=;
        b=dHJrfcNzaetH3bbisn23KT+YSXnTXFKUkiJAr5z1DxcZYLMlz/lE4vsNDWBEwQBaUC
         xQh+crKDLBSp3nGEGfblJ9JZvpk2CDWAITgUe1j/KZL1vLMkUvkqFOteDnS8P5iqgS0Q
         MDpRX8bJrOLCrOge6ylTgULAaRKOY2Cu11k2oN6U4VleH+g+dD6VI3rzVNpBMmD8vcep
         VJyr5dosWaVsWv7jWtOZOBKgBtooxsDKNRvuqjDyKmJIiW1L22xe8x77gbWQg3hoT5iO
         CpacHg8JJFXhTSO0gFCpvGP18gHly4eVwHL4Zswab71yT6pc49FP/30BFh3gQRpljHBf
         iFRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3zGJAhgFDwkd80ynPj6KmZxJkG/IUvyjGxtqJQjUH6Q=;
        b=FSCh/XNpa0dDtcXrNTyNx6u5fCVaXGjOYr8AalY+P9gDwHSVEUHX6ymHJprX6QInLE
         yG5DUT6MPRNtQWOstjmFIFmJypwsFHzn1Ndnt3UgGp2iE7aGq2pM+tHpEb5okGlmdpI+
         +f8oQUoGmkAOA15KsIGBX6YbxUNkinUTcaVwF3k4mlL3mIGzaz/EAEANfVdOTeRICYrX
         tvQLXPx0DoltOkhS/lY1znHc4K1joMSD0EtWhlSyUsbCfi0JJHXscHUCaIHipZVYjFzj
         mlr3EHzfuNURzecAm4hSoZx7WIisOZqw/xmg/NftpHdTzW2FxhXaTUq6BLAhZWYw5yHV
         b9XA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZob5pVi7d8G5XdUnkiYKqSo5y81wqz4y01oimWOkV2e0iEI+Og
	+FiFaBBMnzFGcVPSWg7bCRA=
X-Google-Smtp-Source: APiQypJ91Xw+w/cNrhKPIw7n58w8Dh+Dcc8+Ud6ftqGaqPSAKxNUhOU+nwCPSLdlPUZITyw+rcA/0w==
X-Received: by 2002:a9d:784d:: with SMTP id c13mr898996otm.137.1587591123869;
        Wed, 22 Apr 2020 14:32:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d485:: with SMTP id l127ls411221oig.9.gmail; Wed, 22 Apr
 2020 14:32:03 -0700 (PDT)
X-Received: by 2002:aca:1904:: with SMTP id l4mr815876oii.106.1587591123182;
        Wed, 22 Apr 2020 14:32:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587591123; cv=none;
        d=google.com; s=arc-20160816;
        b=TBHfkM/JRMndnOJ5e93fhRqGp/TasLOz52j8NkiQ3jIQb+ygrNNdBAWLe7JC3QGiXl
         N0gNSmlG2KHTrVJjEXavoC+FC+PfMstGJo4sl2Dgl8cSDmVWyIvrlepGjYJynq17UUcO
         tYs8N1GP96p7c/EG24qyYijRqbM7jXRSJ7+wq326klqExhtd0LOj48ZANkQVWm683mLi
         eW1xARrWjn1UtzaAh41hMhg4JmDupE/yIkPKrIaD+CVJXLSIgkOiuH4Xh8NqHYACBV4p
         NGGPpYXDrAYiNJIR6WPGBvbTO3cS/e4SMi9XaYKR/eXYoD5lHymD490EfQDivSmYKFpZ
         aJPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=+WYIg4RAMlWM7Kf2aYaI6IHSuB8btJKPWzUnEhkHm4Y=;
        b=tP8DrpO1g5zM9UOONHBt2o8e6WE7cuHSnGLaHd3M+4vl8MkdLKi1SyF46FwqJmQ96h
         Kq1YiV6UWjP4mlMmo+W+YWIW8q07SXchAaqg/Rs+9mFmP3UuB9bdbQpYNavAsGqJ/14v
         ZkkexQmYGop3jT8qwhJktFEecArnmzVlGrN/ZWutS3NAd8ANYx/+NGW4748uYxDIq9zF
         GREdwCtP4tnWRpxp3FeL//q9r61qrqD2SF3+n+h/FrTm0++HAOPUE77RnAaT/9aVLQzl
         awzEnO25rNFuJhWjss4TVKHpEzgIA1Q6tWuijWEQKC6oMkp8bQh6vxoFo6RsRc6a2F52
         GFBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=NdOunxgY;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id o6si96953otk.5.2020.04.22.14.32.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Apr 2020 14:32:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id g74so4097127qke.13
        for <kasan-dev@googlegroups.com>; Wed, 22 Apr 2020 14:32:03 -0700 (PDT)
X-Received: by 2002:a37:6754:: with SMTP id b81mr343164qkc.129.1587591122484;
        Wed, 22 Apr 2020 14:32:02 -0700 (PDT)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id l13sm362769qtj.17.2020.04.22.14.32.01
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 Apr 2020 14:32:01 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 13.4 \(3608.80.23.2.2\))
Subject: Re: AMD boot woe due to "x86/mm: Cleanup pgprot_4k_2_large() and
 pgprot_large_2_4k()"
From: Qian Cai <cai@lca.pw>
In-Reply-To: <20200422170116.GA28345@lst.de>
Date: Wed, 22 Apr 2020 17:32:00 -0400
Cc: Borislav Petkov <bp@suse.de>,
 "Peter Zijlstra (Intel)" <peterz@infradead.org>,
 x86 <x86@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
Content-Transfer-Encoding: quoted-printable
Message-Id: <2568586B-B1F7-47F9-8B6F-6A4C0E5280A8@lca.pw>
References: <1ED37D02-125F-4919-861A-371981581D9E@lca.pw>
 <20200422170116.GA28345@lst.de>
To: Christoph Hellwig <hch@lst.de>
X-Mailer: Apple Mail (2.3608.80.23.2.2)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=NdOunxgY;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as
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



> On Apr 22, 2020, at 1:01 PM, Christoph Hellwig <hch@lst.de> wrote:
>=20
> On Wed, Apr 22, 2020 at 11:55:54AM -0400, Qian Cai wrote:
>> Reverted the linux-next commit and its dependency,
>>=20
>> a85573f7e741 ("x86/mm: Unexport __cachemode2pte_tbl=E2=80=9D)
>> 9e294786c89a (=E2=80=9Cx86/mm: Cleanup pgprot_4k_2_large() and pgprot_la=
rge_2_4k()=E2=80=9D)
>>=20
>> fixed crashes or hard reset on AMD machines during boot that have been f=
lagged by
>> KASAN in different forms indicating some sort of memory corruption with =
this config,
>=20
> Interesting.  Your config seems to boot fine in my VM until the point
> where the lack of virtio-blk support stops it from mounting the root
> file system.
>=20
> Looking at the patch I found one bug, although that should not affect
> your config (it should use the pgprotval_t type), and one difference
> that could affect code generation, although I prefer the new version
> (use of __pgprot vs a local variable + pgprot_val()).
>=20
> Two patches attached, can you try them?
> <0001-x86-Use-pgprotval_t-in-protval_4k_2_large-and-pgprot.patch><0002-fo=
o.patch>

This fixed the sucker,

diff --git a/arch/x86/mm/pgtable.c b/arch/x86/mm/pgtable.c
index edf9cea4871f..c54d1d0a8e3b 100644
--- a/arch/x86/mm/pgtable.c
+++ b/arch/x86/mm/pgtable.c
@@ -708,7 +708,7 @@ int pud_set_huge(pud_t *pud, phys_addr_t addr, pgprot_t=
 prot)
=20
        set_pte((pte_t *)pud, pfn_pte(
                (u64)addr >> PAGE_SHIFT,
-               __pgprot(protval_4k_2_large(pgprot_val(prot) | _PAGE_PSE)))=
);
+               __pgprot(protval_4k_2_large(pgprot_val(prot)) | _PAGE_PSE))=
);
=20
        return 1;
 }

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/2568586B-B1F7-47F9-8B6F-6A4C0E5280A8%40lca.pw.
