Return-Path: <kasan-dev+bncBCXLBLOA7IGBB6X3XTXQKGQEFDRA4PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 1524E11809A
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 07:40:59 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id l2sf3657745lfk.23
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Dec 2019 22:40:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575960058; cv=pass;
        d=google.com; s=arc-20160816;
        b=UL5/EBHMYygEOu+xiD6ssyfRXnQldP1Q5Rt5baUsr5jl2aqImJaAgPXwpT3v5sa4qm
         GyOlCSZvQPC+1BsLLortXoRRaadVP67Kc/U2IxCChouwPEuPfhOta4FnPBf/tL7m3Mwx
         Su6pIq9r9atUiGqC3eQX2fv2RD93skxN/pqzQhVVTiIZo7iX5IzHW1hL/opNLgPz9XBa
         qzpa9kbtXrbrLQBtLDNjNy3E6cP+k+PVtD911yLmpP2PczNhtrVyAFtP29++X3I76u7A
         SBmcNe6Kg6QgUyYD1kdiHjt41v+O2FF8wGgrjIMe81eRCVVJY1WLy8MPzB2DJJHJ9yKW
         rNdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=a+VdOIMMQlvtpPBcKYqugDl6x3RuNTwKRREp7T0hYYI=;
        b=fL3quZVjKkxiDrPFxrQqrQHHOyG+LohdmO2akPnBkMcVijouyjKrsf125Og39Gv6U8
         YcW8Fdq11sDMJG6KHMqvzxBXRslMkGxt21iyHALv2WhT4QQu8qImJNThT0CEDkT8ldWg
         sCCsb0RX2VDGQI5hLidWaqUI0SX97LzqpFMYSLHMhWnhSaRpJQINhqTeenkYeKp2duf3
         g5La0dluiz3Ds9gJV+ukq3Sr0X8fTFk5nn4P6vCM8kVWiZbbiOw/ll+0dFNur1r4J02b
         FGr+B1rj6mTzQpIZdtSGqPMlgVOkSzOh/MgwPKKjpsgiM6GWh9icQVejZGEEBccHHNxi
         xLlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=tAL2i83x;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a+VdOIMMQlvtpPBcKYqugDl6x3RuNTwKRREp7T0hYYI=;
        b=Ch50AszPKFbGKhFWS4uxCpNloYsa9mr06Q/ytRVM757BqQaru8jez9LZFydQh6YbYv
         NRvaJ4Ki58JPsF1Yq8eh+vWga1F+05L5F6G1Lh/DE6Slbkwht2fJg8n6e4VxMQ5gv6Zu
         HyROLt+VcLz3XMB9yzxgf+WjeHS3lszcEzCXVqYSPWG1hO5Pgl+57y81bFsB1AgM4cRw
         m3sLa4hEw1hutVO57+StxF4Mg7vhSNt9T6uRP0PWFXUZrhygQTHKZoCrUf/DI9Ybr9q/
         8+mat9B1C/4DtHyMEqbS/Yd+GefxWXq0AxE/9S3bfUujVVKfqyG/EZbIjxGzvK5FoYxX
         p9ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a+VdOIMMQlvtpPBcKYqugDl6x3RuNTwKRREp7T0hYYI=;
        b=og3VXm7NuiNbNc1pGIMjLR9pxqf/RF2iUL9vLHyD0ACSipicZoQ3stXO2iWwhbkOKB
         lHLO3MRSBH+n5VvWTcMRplV7f4f4s5xTpJioN0uMX9Q6sJYavQHU1m4s6djC5A81Hd7D
         OYlWrNJHCYJRU4UFDpU2BBOEyeKVRDzZrv25aXScgFz5yJ6zdrz21yASij8NUm6pKeu2
         cTHN6ktos9mEPKbG80iqvJHomMCQpKbVLI1fEYtEtMin7DEMxWzpcoK4+7jWX06mOg9M
         3k6bvodEjfNM0j93YZwuaN+IVNTpmutRFXOVPRDISASx2eevPA9OqMNRtg7u7vAWU9NR
         LRiQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVB3vIT1/mQsvC/dB7QLR60Dt6+rLmoq40eEfVp5XOGOz/fdsZy
	euiK1AHq33vbIPqhonu+3HQ=
X-Google-Smtp-Source: APXvYqxSwHOaN7cQOJd/7VI6mWWRALK0kpAgp9JJsYZoducE3LuamXP3UVQkBjP8CFS7KQ0OoaZsTg==
X-Received: by 2002:a19:6a04:: with SMTP id u4mr7600769lfu.62.1575960058690;
        Mon, 09 Dec 2019 22:40:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a179:: with SMTP id u25ls1891838ljl.1.gmail; Mon, 09 Dec
 2019 22:40:57 -0800 (PST)
X-Received: by 2002:a2e:6e03:: with SMTP id j3mr7935053ljc.27.1575960057852;
        Mon, 09 Dec 2019 22:40:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575960057; cv=none;
        d=google.com; s=arc-20160816;
        b=WRH+e5ZFRHcwsJ9VPPKkb2VH7SITEqudIlVZdatLiHBFQ12WCmUYNBUvgu3Gl3g3ua
         PuIhkWNHRb0+sNgGaeNfNBXOsTWSqY4tILzJoSoDWIVM59SH/Fns+DQmd3I+WpUR36h5
         Io6OUCyHgH4frVyOTyugCwMwER6vdPZ7qgeJYRhNVQ8QawdhKEz0vF+mJWK8yIgTLUSs
         +QsHikTEiXSfgj8/9zOxX66hDhnjst/CEM1D6zCkuQbmJ8K701wEL7Ra11hFsMvMHxp7
         NgxdIRdUiJrU7SurZL4wLnNo4hpFBN2lpD5EXDBWHUspm3rDvmys8fPmbMZ+WFA47lu7
         zXQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject
         :dkim-signature;
        bh=oSR9uIzDt/rEY6/KSJx3AbUqofk/Ep6fxitZcrpxY2s=;
        b=rUSKDkctdJNsftKR+aH28EXENfcH8sr9TSRwxSueDWyWZY0fZpx/L/FpFGqNu8yM6F
         WtNosOo3mUnC27O+8scsyBEqMih9Ajz76r4qaxe7q3PhWvRC4IahNZOExOrpZAHRuh18
         oLle7BJPTzYGR5a+0EsmEtVIQLLIf+TgR6SRUzb18TKF6+fqcOxn/mt7xV1kv6J8gl6h
         DQyDi/rdETXd5vOqj3EhBJsRRFyYPTL46+0b/Bjn7u8URJFPfMsImKDBgv8LBZM3nYQJ
         yUQcuFVrn0LbQmNnY2q5a1eKydllWxIfaqeNy5m3nFrjJQ/5leYBveMegADUb4k3o77s
         WY+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=tAL2i83x;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id o24si113242lji.4.2019.12.09.22.40.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Dec 2019 22:40:57 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-ext [192.168.12.233])
	by localhost (Postfix) with ESMTP id 47X9S80z1Rz9vBn0;
	Tue, 10 Dec 2019 07:40:56 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id 826r04EkLdd7; Tue, 10 Dec 2019 07:40:56 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 47X9S771q6z9vBmy;
	Tue, 10 Dec 2019 07:40:55 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id CEE348B802;
	Tue, 10 Dec 2019 07:40:56 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id k5RN-hFh1dZD; Tue, 10 Dec 2019 07:40:56 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id EE1AC8B754;
	Tue, 10 Dec 2019 07:40:55 +0100 (CET)
Subject: Re: [PATCH v2 3/4] kasan: Document support on 32-bit powerpc
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 linux-s390@vger.kernel.org, linux-xtensa@linux-xtensa.org,
 linux-arch@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
References: <20191210044714.27265-1-dja@axtens.net>
 <20191210044714.27265-4-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <8b64ce35-01df-3c0f-2695-40633c324331@c-s.fr>
Date: Tue, 10 Dec 2019 07:40:55 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.1
MIME-Version: 1.0
In-Reply-To: <20191210044714.27265-4-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=tAL2i83x;       spf=pass (google.com:
 domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted
 sender) smtp.mailfrom=christophe.leroy@c-s.fr
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



Le 10/12/2019 =C3=A0 05:47, Daniel Axtens a =C3=A9crit=C2=A0:
> KASAN is supported on 32-bit powerpc and the docs should reflect this.
>=20
> Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
> Signed-off-by: Daniel Axtens <dja@axtens.net>

Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>

> ---
>   Documentation/dev-tools/kasan.rst |  3 ++-
>   Documentation/powerpc/kasan.txt   | 12 ++++++++++++
>   2 files changed, 14 insertions(+), 1 deletion(-)
>   create mode 100644 Documentation/powerpc/kasan.txt
>=20

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/8b64ce35-01df-3c0f-2695-40633c324331%40c-s.fr.
