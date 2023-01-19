Return-Path: <kasan-dev+bncBCULDUPM3QHRBBFDUOPAMGQE7J2K57I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id A0376673109
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Jan 2023 06:13:42 +0100 (CET)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-15f0a1b7764sf616397fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Jan 2023 21:13:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674105221; cv=pass;
        d=google.com; s=arc-20160816;
        b=CI/Fel1iN3dHyQ4goxNcpLE2xTWeBeuTi1O+6yHDFXj0s+4gDkopyBhMc9gSCeF4iz
         4IzYc1ljVQPRtNYYE5TGgU74BCHNCnmF8srhfZoVSsuPXy8AYVxoqtTnypoYBKBcJh3l
         VLbti7fcjHPFYdDlaX6f/B4plGfRaXtrTRrlkBaEYRq/RKfijGegsyciN7GvHaVT6AlT
         1cHm2k54kjEWayZ9ObuhuEYhtcGftCSXkbM6rLSqIbBG1ujuM1/NFlyqHWqcNqwsWpND
         J7Qog3AKS4/dlpouA+X1QyT2rKBjLvagJXgN68dW+xw1urYUFrPX4GmTNXPWnfIIZFDE
         ao+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:organization
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:wdcironportexception:ironport-sdr
         :ironport-sdr:dkim-signature;
        bh=DEQQhJ+ImN0xpsXur2jyMwK5tl6caYvhi49pWx8meVo=;
        b=B3n7r0XycTVCpfVjbeKiEH071ZhOLGr9rEEjoMBdUWaA2wduwifQAuDUXd8bO+wCY9
         DlomMUtZeNhVPigj+bE/IauZrs6Ni1VXGC12q+49Vy0NzpxszfU+UTzK51oiNcuvwwFK
         g3kVM9DxftYlIgIkImVpfnKQ3Xn/d4nSu/CZ7qVQyjU9MYsWKEeLv6yOA38LJ0uzudAY
         77XI7jNIIPNYFrgNcYfBdvw3euRxSSKOcLhp8KHM6P/sUIUeCLTLsMP+InpJGX8S6C9t
         +pCsFmB7t3Y4XYAV5LTBz7hSYgFccBS+Jzm5fvvaHbR0uMhm1qBMMIhFr0R5ZZxPOpf1
         RcJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@wdc.com header.s=dkim.wdc.com header.b=dlwtgW0M;
       dkim=pass header.i=@opensource.wdc.com header.s=dkim header.b=N4bP7ytV;
       spf=pass (google.com: domain of prvs=37646b54f=damien.lemoal@opensource.wdc.com designates 68.232.141.245 as permitted sender) smtp.mailfrom="prvs=37646b54f=damien.lemoal@opensource.wdc.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=opensource.wdc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :organization:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:wdcironportexception
         :ironport-sdr:ironport-sdr:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DEQQhJ+ImN0xpsXur2jyMwK5tl6caYvhi49pWx8meVo=;
        b=sfBrbidv2j4H+uDPeJT8wOJXRtIYoOMl/imSoScljvLr8SvjiJTvFuAF8D8DGwc4P0
         fMbGrELhz0c3vJtnDh0re2g0U0YTe5ayAcOIOy8cN9VTWBbwPcaL1uv7K8VUsQasZn+X
         vtXNGvNO5dkeeMytUs/YeBJAowF2NOtbl9dt5GIReF6A22KfdLsG/ytSMnzS+3rW+U1E
         h7IbCQ17o/ODg7wveyTaEWgygIl75yNia8Qfe1/TiMsOPYZpPrx3yzuMbi/vYbFMzOPo
         wBrFq7mxTj/IIBuZUJEONhvlV1z/+h9BFVzz3zMmZqbJIjWgBuymn/4vBTX0AH8DuJcy
         YzLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :organization:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:wdcironportexception
         :ironport-sdr:ironport-sdr:x-gm-message-state:from:to:cc:subject
         :date:message-id:reply-to;
        bh=DEQQhJ+ImN0xpsXur2jyMwK5tl6caYvhi49pWx8meVo=;
        b=X7aVX8uBd5vrgwoXW3pBsOBZ17HeaNOe3XiI1VTFnrJ03PCZSpF4mmj+Ad013nCVhv
         5hvXEOJuRm8dTUgpOb6ZlGnfEpJREr5lOCBy7NGkGj+UxhPax0YuTujh572bKEH7tNKJ
         i/9bBSzJnbFUdwsllRFuZ4YCmTbdTxmlnVfQag8FjINo44NXctNAB1xhdAYPuOt0tkBn
         /2Jp0dxXgjUNdwXd4DRYXepoeSn/S814MLqkIdm/pNmkeRhLsrE8WRQB2SCG3aOHeTD2
         KY2lXXx7meReNaNeR2OE99FVdmkHXndnj1Ek1XJ4zit6WYLz19Malhv/GGw73r5TB+4Y
         Oepw==
X-Gm-Message-State: AFqh2kow+D9RRRWslAXKlvHCrFPlVokJlDB4KqiBkOpKa5M1Mx5rFZMp
	q9r+1h6Hn60ucBsXyKQNz68=
X-Google-Smtp-Source: AMrXdXudK5gE7mAm76cYz3rKOb0G0wzYOPg8ZoALRxNJ67Xf+4zW999SlKXVon8/wZUrOaQgtjAutw==
X-Received: by 2002:a05:6808:c4:b0:35b:e3c4:afed with SMTP id t4-20020a05680800c400b0035be3c4afedmr662973oic.44.1674105221074;
        Wed, 18 Jan 2023 21:13:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b6a9:b0:13c:4c86:219f with SMTP id
 cy41-20020a056870b6a900b0013c4c86219fls228074oab.7.-pod-prod-gmail; Wed, 18
 Jan 2023 21:13:40 -0800 (PST)
X-Received: by 2002:a05:6870:fd99:b0:15f:ed7:c02d with SMTP id ma25-20020a056870fd9900b0015f0ed7c02dmr5496735oab.55.1674105220662;
        Wed, 18 Jan 2023 21:13:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674105220; cv=none;
        d=google.com; s=arc-20160816;
        b=mrfm/iuzjyydR7OCMN7L/QZOen7fMwIsAISfWRmosGWiMEEo3pvDDoDsMSMumiqYXe
         h6spZJATZFHtaK//7/5YgXVTpw1I0DSXoqiIyUN6a7tVHBuf1EkuBlPzKK9lfnzK0xDK
         IJm9duelXyItRmfZAaa46A2XUUlqs+JlUxmjGS7GHkbvzlV2XURvTowrNAQYWMJyl6W8
         l3f+UCZzmKN7lOFPPYgrdbzOgsmt0YRWoTFTTI99ZkKxRE2TfD06SK5QExt0LUxt/Qa4
         y7E8TaqwxTV0HkZysogiBjhXvZsxoyPcHjEOfLJzyET2Q1fPr5vqKCIBO3ctf3SenVQT
         CgNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:organization:from:references
         :cc:to:content-language:subject:user-agent:mime-version:date
         :message-id:dkim-signature:wdcironportexception:ironport-sdr
         :ironport-sdr:dkim-signature;
        bh=LljVYsCsIeujL3oabihMDLsUnXHTQI56qwFgIvvuHAM=;
        b=S5DYSP/85oPMv+5fpzqSvSd8/wMl4agst15G7RZM29aftWjsl1Ulo7ZfFRwtXJn7zs
         j1VQ2nvEHLutziZ3WmaE+rlo1fOi3O9F5xBsPF19K2ZQVkf5ATFYHPOXMxsE9IYkZ+s7
         31c84S52hy0Bew10uV/eLQ4xz0jw+RMmbXc0kHMshlxZoUIPbtMbUpbfLlQ3scSpX1Zr
         vxvyBU2GBFVs2iYinxnrQdIJzYpidZgyTneufzbRUcPushzKy79UGRG86lr5NemlgyZ5
         cL67u2mOLlODnmWU3Inew47AK5885sqhsh7xwc7y2niNCjRA7D5MSde3whjGsUngNiPZ
         GGOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@wdc.com header.s=dkim.wdc.com header.b=dlwtgW0M;
       dkim=pass header.i=@opensource.wdc.com header.s=dkim header.b=N4bP7ytV;
       spf=pass (google.com: domain of prvs=37646b54f=damien.lemoal@opensource.wdc.com designates 68.232.141.245 as permitted sender) smtp.mailfrom="prvs=37646b54f=damien.lemoal@opensource.wdc.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=opensource.wdc.com
Received: from esa1.hgst.iphmx.com (esa1.hgst.iphmx.com. [68.232.141.245])
        by gmr-mx.google.com with ESMTPS id l2-20020a4abe02000000b004a399d01471si253251oop.1.2023.01.18.21.13.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 18 Jan 2023 21:13:40 -0800 (PST)
Received-SPF: pass (google.com: domain of prvs=37646b54f=damien.lemoal@opensource.wdc.com designates 68.232.141.245 as permitted sender) client-ip=68.232.141.245;
X-IronPort-AV: E=Sophos;i="5.97,228,1669046400"; 
   d="scan'208";a="333200748"
Received: from h199-255-45-15.hgst.com (HELO uls-op-cesaep02.wdc.com) ([199.255.45.15])
  by ob1.hgst.iphmx.com with ESMTP; 19 Jan 2023 13:13:39 +0800
IronPort-SDR: eSIm+k2Zs83n/o5WqcnZ/U2KGhfCetNgtbArOYyvaVXK/xcX4dhTmluZ1fFGlZFERuldBOqOeR
 G34h3q6dKGM7tni/oEFuOGzhdb3td8ZzayE9LQlNIRAlAJnovXbTEf8+CFpj6Y+RK2VGma3Gyj
 H2/PJAkJNHtTR51pDmztCU0QwNQ5fZbPpHetaWHQHOQeZ5MN47hNaO8KOh2p7E3HYblFqZeQNn
 ZCDadz/ybURjtvJ2zXvMewd3PpV+QqxN1H/dwXQWm/QAolT5Q1vWrn+N8tK1ilyxjgSo6OWoCt
 7Kk=
Received: from uls-op-cesaip01.wdc.com ([10.248.3.36])
  by uls-op-cesaep02.wdc.com with ESMTP/TLS/ECDHE-RSA-AES128-GCM-SHA256; 18 Jan 2023 20:25:34 -0800
IronPort-SDR: H4//i6ne3fRzCsyicqPwxFOlHuav6PwjzTWCpjgzlrWZa7aRROhCrJG0hg3N8k+VK/3WFiFe0f
 jj/RoreNLmFj5HGMgtOCflIe0K39jNDUM63Bqs7GRhvgKw/tAGp0UBvCpN7fq+UTeeVUNMxn/B
 iA42eX9UknH/gIShBWTYpa9kqlAue/EViCqnOTVmKjJPmyhST9xgP1OcQ5L9EkbrYQfC10qKE0
 ph764TC7phsi96RSQykSteiKSmtVeYqOgwLelXsZ9EZRw6xkDs7ZLq6iPFmZ+WS9CKSLmsCyEW
 sMU=
WDCIronportException: Internal
Received: from usg-ed-osssrv.wdc.com ([10.3.10.180])
  by uls-op-cesaip01.wdc.com with ESMTP/TLS/ECDHE-RSA-AES128-GCM-SHA256; 18 Jan 2023 21:13:39 -0800
Received: from usg-ed-osssrv.wdc.com (usg-ed-osssrv.wdc.com [127.0.0.1])
	by usg-ed-osssrv.wdc.com (Postfix) with ESMTP id 4Ny9l71BtSz1RwqL
	for <kasan-dev@googlegroups.com>; Wed, 18 Jan 2023 21:13:39 -0800 (PST)
X-Virus-Scanned: amavisd-new at usg-ed-osssrv.wdc.com
Received: from usg-ed-osssrv.wdc.com ([127.0.0.1])
	by usg-ed-osssrv.wdc.com (usg-ed-osssrv.wdc.com [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id 7B4KS2sUt7Pq for <kasan-dev@googlegroups.com>;
	Wed, 18 Jan 2023 21:13:38 -0800 (PST)
Received: from [10.89.84.31] (c02drav6md6t.dhcp.fujisawa.hgst.com [10.89.84.31])
	by usg-ed-osssrv.wdc.com (Postfix) with ESMTPSA id 4Ny9l54xkMz1RvLy;
	Wed, 18 Jan 2023 21:13:37 -0800 (PST)
Message-ID: <29f91612-bcb7-e9a7-ec14-b89efe455b1f@opensource.wdc.com>
Date: Thu, 19 Jan 2023 14:13:36 +0900
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:102.0)
 Gecko/20100101 Thunderbird/102.6.1
Subject: Re: Lockdep splat with xfs
Content-Language: en-US
To: Dave Chinner <david@fromorbit.com>
Cc: "linux-xfs@vger.kernel.org" <linux-xfs@vger.kernel.org>,
 Dave Chinner <dchinner@redhat.com>, "Darrick J. Wong" <djwong@kernel.org>,
 kasan-dev@googlegroups.com, Andrey Ryabinin <ryabinin.a.a@gmail.com>
References: <f9ff999a-e170-b66b-7caf-293f2b147ac2@opensource.wdc.com>
 <20230119045253.GI360264@dread.disaster.area>
From: "'Damien Le Moal' via kasan-dev" <kasan-dev@googlegroups.com>
Organization: Western Digital Research
In-Reply-To: <20230119045253.GI360264@dread.disaster.area>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: damien.lemoal@opensource.wdc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@wdc.com header.s=dkim.wdc.com header.b=dlwtgW0M;       dkim=pass
 header.i=@opensource.wdc.com header.s=dkim header.b=N4bP7ytV;       spf=pass
 (google.com: domain of prvs=37646b54f=damien.lemoal@opensource.wdc.com
 designates 68.232.141.245 as permitted sender) smtp.mailfrom="prvs=37646b54f=damien.lemoal@opensource.wdc.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=opensource.wdc.com
X-Original-From: Damien Le Moal <damien.lemoal@opensource.wdc.com>
Reply-To: Damien Le Moal <damien.lemoal@opensource.wdc.com>
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

On 2023/01/19 13:52, Dave Chinner wrote:
> It's a false positive, and the allocation context it comes from
> in XFS is documented as needing to avoid lockdep tracking because
> this path is know to trigger false positive memory reclaim recursion
> reports:
> 
>         if (!args->value) {
>                 args->value = kvmalloc(valuelen, GFP_KERNEL | __GFP_NOLOCKDEP);
>                 if (!args->value)
>                         return -ENOMEM;
>         }
>         args->valuelen = valuelen;
> 
> 
> XFS is telling the allocator not to track this allocation with
> lockdep, and that is getting passed down through the allocator which
> has not passed it to lockdep (correct behaviour!), but then KASAN is
> trying to track the allocation and that needs to do a memory
> allocation.  __stack_depot_save() is passed the gfp mask from the
> allocation context so it has __GFP_NOLOCKDEP right there, but it
> does:
> 
>         if (unlikely(can_alloc && !smp_load_acquire(&next_slab_inited))) {
>                 /*
>                  * Zero out zone modifiers, as we don't have specific zone
>                  * requirements. Keep the flags related to allocation in atomic
>                  * contexts and I/O.
>                  */
>                 alloc_flags &= ~GFP_ZONEMASK;
>>>>>>>>         alloc_flags &= (GFP_ATOMIC | GFP_KERNEL);
>                 alloc_flags |= __GFP_NOWARN;
>                 page = alloc_pages(alloc_flags, STACK_ALLOC_ORDER);
> 
> It masks masks out anything other than GFP_ATOMIC and GFP_KERNEL
> related flags. This drops __GFP_NOLOCKDEP on the floor, hence
> lockdep tracks an allocation in a context we've explicitly said not
> to track. Hence lockdep (correctly!) explodes later when the
> false positive "lock inode in reclaim context" situation triggers.
> 
> This is a KASAN bug. It should not be dropping __GFP_NOLOCKDEP from
> the allocation context flags.

OK. Thanks for the explanation !

-- 
Damien Le Moal
Western Digital Research

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/29f91612-bcb7-e9a7-ec14-b89efe455b1f%40opensource.wdc.com.
