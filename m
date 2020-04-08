Return-Path: <kasan-dev+bncBCFYN6ELYIORBX4CXH2AKGQECH5AHEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id 378731A2B0E
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Apr 2020 23:25:53 +0200 (CEST)
Received: by mail-vk1-xa37.google.com with SMTP id e69sf664522vke.11
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Apr 2020 14:25:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586381152; cv=pass;
        d=google.com; s=arc-20160816;
        b=q6VLIwm1o9xGOTSRFZxiqvqFE8bMrrvy63d94SIb9jqZpN+Gb5K2pgKtYwG3EBo5Qs
         9DGDUHjiPeM4aE6PuhuyT63pLK3YHIeBwYWcHlch7cjivq4cf6pbSX2Pg3DSpJS2eZTZ
         cUusNwDbAPWkF7Pq1dKIFt4HwcmMbKqogupVkJR/XY5yOrFT2PbfNX4IN5pL0VBB01VQ
         Ry965L34j2XlWOLyFbyewzjUNUA0XVVDZYQbpg1H0naCEMBu3m10eulUp4tNf+uhjFSD
         QeyP5zJlZmmC8MDoQjTzS43H151U/BRdNNIRMSQLaaPCwSYkry1di4cXdF4+TSXR/5eJ
         zR0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=KAQz9OF1vN5ybRD26Es5aQc8UpNQ48iZPbVuX20qqUA=;
        b=qw2hlEICW4EaAp2UUZNxz9SKi0xRWhvFJgBUe/52d54xmMSSZIHE0LVQinqr7C+kAm
         /ECjAhPIC2PddaGNk1xGvcAY5vzzUIhG3Ce6Flxti9ReOFf4ILLcZI1Le4ck4qFsKn6G
         KWUIq3LVWGR53pEdP28saSfsyW2iUhYEIBWt1IBgEwuibNdm8X0DwgBp1b7EqYBCxgQf
         wAioB5hiaumXVYUy0fc+V+J2amoiuF06rKM01QpjskIxAeVDly9fpOUn65FGmxHzSBmz
         Q2dFmC5RuwBTU0gBWMocT/QFU8DpOTV8ApEAk8A+laBEzE0g1RPC+N/SIcrSTcgNVYME
         cAmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Z0Ze2MZY;
       spf=pass (google.com: domain of pbonzini@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KAQz9OF1vN5ybRD26Es5aQc8UpNQ48iZPbVuX20qqUA=;
        b=AbNp3X7jskvOPW2vmszSFLdYGTFNxWJhcbNY8HPwNGB5ubnLA/8+bEOlp6seO1263X
         7i6cXUyY5/CUPYr+jj/RRU3N3IF3GrLVRddnLTvVdXPExcUKK98XBs8PFip1DpXUK9e/
         XzPJuMR6QZ+X4nxTcexhrYV6llNPa8HT7tb0iy9g6wml64ciwngcB/bNW5dcwgmO5dyc
         r6hmOZ4AovLpOeO44I2vmY74Q/+L+nE8T6B9Ah3ALslTvRu/NYiHLXjQp3A3DpTKU2T5
         cdxr7Rr9PQRyJd9r56RdKJh1LU9L+s+YNjizW9g1r9CvaI21ghGgzGHp1AhcAVaVe2AU
         WyaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KAQz9OF1vN5ybRD26Es5aQc8UpNQ48iZPbVuX20qqUA=;
        b=XNddhLhS0PeC45xTvSd5xbVdeixpYB21FLwQS+ngsMaD8e42K8NEW1H7C19HV/4HHr
         iAmK/vN7N8w4mvt4tA3U8mWInl3lIT41yGi7kcgPg3Maprtgth6hxGGc2G4lHnkcIBIf
         CG3sehyCaDfwlksbUz+mY3cLRaKN2AxTtNTXv72f2+hfqBnECcZwGmQvgmLpx0nqtxme
         LVrtmkLZTMZcXKVtLq8xo+bYp0UEMmJLC2dK7eXgbC9lnTzMi5KZxjSomaNPmTRmAZRe
         NVZd46yBB03CkTUu3Q+73XoK9aLzlMChdV1EA36dGPOD+cEZH8Vekq9yMYgCNM65twMA
         VISw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYI0rCZrRaea4gvyoFMv3h7LTV6mVsixsqcYSYwuqWpxseAFx4y
	RHugoyqwjeJZoTgAOHjMOao=
X-Google-Smtp-Source: APiQypIGwH13PNa1d1Sn4k/GBWRvhdXSRYcJPTO6XMC4OYsz6pmkX+wzguaC1AY+zGug/CeaGXU+RA==
X-Received: by 2002:a1f:abcc:: with SMTP id u195mr6987538vke.11.1586381152063;
        Wed, 08 Apr 2020 14:25:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:b0:: with SMTP id 45ls58819uaj.11.gmail; Wed, 08 Apr
 2020 14:25:51 -0700 (PDT)
X-Received: by 2002:ab0:2553:: with SMTP id l19mr6931582uan.128.1586381151643;
        Wed, 08 Apr 2020 14:25:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586381151; cv=none;
        d=google.com; s=arc-20160816;
        b=vaDUXm27AhNSfEPXQGF6QVRiWngxjMYOPZf4zbPB/n9a8LrhZ+BbdpN/Xpu96iNoYR
         SkrUuS1L0W1vOcxwyfG1Gwa2IWInF8XSPgJ2FBsbJ2C9gagy1WP6VBLgwHHafqxwiro0
         yuptaUVUf7uZfFSnbpFT6pruVfv0Xa7EvMu+LddJVEHSht3O56hJR9Fv6fpC1ZDoKN2b
         BIe5s6twM63aWgjyXVnPf09UnVx9jDzSWf7sfjll5jKXxwAOIPlpi2/RDiwNz/JT/ini
         RmyDyS61PzIfAnACzmCd0cQlNxO+pAe6dAlS4RdFgSaNhxq3GojJgdIb1s2f4YOCY0o7
         DWNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=UgddkiohhyxQDJgfbskl6P2CS8c0mRL6YeakPaNMpuM=;
        b=b5NcW3t+aZ/Kk9GK5wF0PoSf6drQfgTH/ZEQVMkv5ZOfors+Q0mzhA0CJh6kSwjkE6
         uhpiDpC4U9ADpZPK/37EoFIOpdWdKmXUJqrMBjJk9xXDKj1x0Yc1NPX2B0GiAdyba8tT
         GCQtaebu0Wtk2PbSCD9Yy9WMlkk1n1MnF/TwOOVsqVqL84fN4o1kVbQmf18Gi9aGCV+X
         AFguWGjp2FPqnyhysIM0WLIA+H6qZIiUik+1nBZ4XlT56R6THAM+YAC7BoDyNZot2gMo
         HQUD+vI1OldSSsKA+1vnTLL04K/YUelUbhgnxqH440tCqg+/o+4HG/+Q1I7ovDFMfh2Y
         x+gQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Z0Ze2MZY;
       spf=pass (google.com: domain of pbonzini@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-2.mimecast.com. [207.211.31.81])
        by gmr-mx.google.com with ESMTPS id t191si483005vkt.0.2020.04.08.14.25.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 08 Apr 2020 14:25:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of pbonzini@redhat.com designates 207.211.31.81 as permitted sender) client-ip=207.211.31.81;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-401-ucf-bYlqMziHN7UlQs-LnQ-1; Wed, 08 Apr 2020 17:25:49 -0400
X-MC-Unique: ucf-bYlqMziHN7UlQs-LnQ-1
Received: by mail-wm1-f71.google.com with SMTP id t62so1109633wma.0
        for <kasan-dev@googlegroups.com>; Wed, 08 Apr 2020 14:25:48 -0700 (PDT)
X-Received: by 2002:a1c:2705:: with SMTP id n5mr6375967wmn.94.1586381148142;
        Wed, 08 Apr 2020 14:25:48 -0700 (PDT)
X-Received: by 2002:a1c:2705:: with SMTP id n5mr6375955wmn.94.1586381147897;
        Wed, 08 Apr 2020 14:25:47 -0700 (PDT)
Received: from ?IPv6:2001:b07:6468:f312:9c71:ae6b:ee1c:2d9e? ([2001:b07:6468:f312:9c71:ae6b:ee1c:2d9e])
        by smtp.gmail.com with ESMTPSA id t17sm32671085wrv.53.2020.04.08.14.25.47
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Apr 2020 14:25:47 -0700 (PDT)
Subject: Re: KCSAN + KVM = host reset
To: Qian Cai <cai@lca.pw>, Elver Marco <elver@google.com>
Cc: "paul E. McKenney" <paulmck@kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>,
 kvm@vger.kernel.org
References: <E180B225-BF1E-4153-B399-1DBF8C577A82@lca.pw>
From: Paolo Bonzini <pbonzini@redhat.com>
Message-ID: <fb39d3d2-063e-b828-af1c-01f91d9be31c@redhat.com>
Date: Wed, 8 Apr 2020 23:25:45 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.5.0
MIME-Version: 1.0
In-Reply-To: <E180B225-BF1E-4153-B399-1DBF8C577A82@lca.pw>
Content-Language: en-US
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pbonzini@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Z0Ze2MZY;
       spf=pass (google.com: domain of pbonzini@redhat.com designates
 207.211.31.81 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 08/04/20 22:59, Qian Cai wrote:
> Running a simple thing on this AMD host would trigger a reset right away.
> Unselect KCSAN kconfig makes everything work fine (the host would also
> reset If only "echo off > /sys/kernel/debug/kcsan=E2=80=9D before running=
 qemu-kvm).

Is this a regression or something you've just started to play with?  (If
anything, the assembly language conversion of the AMD world switch that
is in linux-next could have reduced the likelihood of such a failure,
not increased it).

Paolo

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/fb39d3d2-063e-b828-af1c-01f91d9be31c%40redhat.com.
