Return-Path: <kasan-dev+bncBDIK727MYIIBBENLVGPAMGQEXIXVCIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id BA294674FB8
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 09:49:22 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id j30-20020adfb31e000000b002be008be32csf845707wrd.13
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 00:49:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674204562; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xqx6M3/ONwLzu+mXbWnzaLries4QG8CUIuyZVY2CO92kMCI34SDTUhqLvLeKs7ocoX
         GYvFYg/RhGXJwO+OTrhf7pZFTyH7sMPK7WMCT1rT6CPQo3mFbxZGIl0o8esRXUi0hv4+
         ok9D10HbvgxEWBwnl833ZIsawgaLRYqoTrR72i1tNUEoZ5uxXkzq4TtIZT8OnFgdv1X4
         BWjwZlte5z5yFKFyvgSEMLsPt/q1GXxM3NIF72iXpVAIbD8I6GPbtaTFhn5rheQHw+w0
         WrGT0Dw5/BTEab7xmRskPHVmR/6IyFso7bUqeXrpaIazaXpLb/WXbp3XbDt3A4gZL/9H
         UPLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=7UaE+N4p/mcsJgr7bK6rZmMGxLNTSbT0EUX9JWGf4Tc=;
        b=p2xxAxObymYAtDrzr3pt54gkjabsbYtnPt5u4hl/+Lz8anS2QaEXPvvqnRxpA6ec6w
         QneF20a5HO0s7/GKvGMplUOoclccMWpP7d+4/q0SPMYk+Dc9eD5Lyed46tUIs5Lxlqu+
         ESJcDyCGQQ+hQbImWn+LUCcmnvGypuIuW/ZY7b4VUjWNQdva6sN5eVWDTpUmJZFyr09i
         //Ah96NoKVKnCyepsUGDR6c+PjLQuysM9+V4ZLi+DtWmwk45V/bXxoav04O0M6JQ0fvb
         DcXQUEuO3KoHmQ2Sn6ndzqs9+Klam5QeaYwtveQcCyDXKewvK++rxilcCvc32gzNNWXI
         nCmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) smtp.mailfrom=glaubitz@zedat.fu-berlin.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=7UaE+N4p/mcsJgr7bK6rZmMGxLNTSbT0EUX9JWGf4Tc=;
        b=qT64CJzLDVs+goW4IMQ4hfS4pgNeh1zvlxK+2Zh4c8L+3zRX1R8apmGoRH1Iu6RR/F
         ccWbfVZqlYZhJYjfiqbgynj117g1FYL8fFprVghH1B8WjfWN3aMKozGwifJaEMRSyBzN
         ez26DoTompkIQmfjCUFuWkyjU5Sf8AWBXu9I845byXGmzOfL4f/KFkZPXu7IvAA3GQF8
         QuokgnaDwuDmA9VUN/ernyl2oZe/nraUtaSp/y/QE3eFcAqjYznUXzMXaMiIIUGgyuEM
         v910xH1Xk23cj9MMf2FkEVaKFm18c5KazfryvU0jJvQqTQEVh+H4nxcl9MJzrxrF7H88
         i37w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7UaE+N4p/mcsJgr7bK6rZmMGxLNTSbT0EUX9JWGf4Tc=;
        b=bnocQI/dCK9Sa5UPTRFlZ18tbO2dyfVoE1KcbwuxHCEZYPIk5ONNc4sLy4hhm1r7dz
         3b4i+6z2NhGQIi2BFsEzbXZYQcVUsQ+TsxTvODls8HCU4W1IhiEVdVvEj4vpbQlym7z8
         LKsKdKGUrhHSesUggV6cSTEKUuNQ3U5Lx9m6OLwIEsEkaHOFR4FklgU7SEGOp360r5Kv
         MuRDLPIi/DnjyMy8WmnbDapOxGET2PFbkV6nFjSN7HHYSxjCvxeAvJmFjs4ZE3Cfanie
         xzf5jGtfGOEg+ZmxTDWzBlLMT+yLmB9aTM5x8ToM5YxeDyxY6nN3NHPIKrPdUc2Jk06k
         X6ZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koHQOR/5EOYMDv+kC+Eahr2bPEJhR2Wy379CLK4ryRfBT/cceK7
	Ckb7XLmL4ckjlt2Wseq7MzM=
X-Google-Smtp-Source: AMrXdXvXUvFfL10jK/MlUjFRx0yugZ0ce41C9lrEKszT3wGvhqCLPuW4ko/DfE/E9pMs8lRXrgr6Gg==
X-Received: by 2002:a1c:7719:0:b0:3db:268e:9319 with SMTP id t25-20020a1c7719000000b003db268e9319mr270926wmi.204.1674204562148;
        Fri, 20 Jan 2023 00:49:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f93:b0:3cf:9be3:73dd with SMTP id
 n19-20020a05600c4f9300b003cf9be373ddls3912171wmq.3.-pod-canary-gmail; Fri, 20
 Jan 2023 00:49:21 -0800 (PST)
X-Received: by 2002:a05:600c:3d8b:b0:3db:262a:8ea with SMTP id bi11-20020a05600c3d8b00b003db262a08eamr4708885wmb.31.1674204561024;
        Fri, 20 Jan 2023 00:49:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674204561; cv=none;
        d=google.com; s=arc-20160816;
        b=FriR6CHJ855kG0cnUb/7KgQXhxfBIDoQ14OaFIUoNENEcwW+eZXHAoeoHNUs1zWXTm
         79lEt50G7fAbGb4FiuYGLLfDED3PGbR0zs3ur1nzYESrWwXymEuW56LT8he7PgUNytv6
         SF+AcYZAJ1xYtZMjU3vlNVLfQx1E9J9Ui67aOOxx1kwoysMt5UwqhXFdODhgLCtKI06Y
         02Yb1dXB6j3JCLgoOevTfi8IPe7G9GkagQOsqj7k6GD7uZNnKXeiwhAzwl/Hce5nQQ/F
         ucufuGzLiYNFqRKxfS+Je5RoO50P3aCbB1Yss45CwVh66mlxzjArIp77kaLyYWUz838T
         sLhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=O1Q6JGgyQ0M9nIV0uBmrpq8KyWCzlkgo1mknB4PV25Q=;
        b=RI6VMrA5Y8aaWsPiYyhovQyAEMu/rIZG2XHeo0F0gGNBAGiBtQsqGmlqV9876Ro9eK
         tO3kqhLWhL29hv9GFp6qWqvI5zOzEluMYzYVFDRYkayGlJkxL/AArRuyVIH6cn7ez3dF
         I7XqK4LpW666/uYoS8amStxLp1j+tX8+qPaWptMW/KZGqdtlytNUqv8zXD5NvpeCPl0A
         v1mfJ9gKpMjNYK/xz1QPsDI2SSV5uwCbwtT1OzpvmSdWoROXMr80I1E2zdB0iSAQw03B
         6Q+7iuPyRbZJFgk0cXwpgd0Z861wBYLG02jxn30f7jb8hJO5PKJVzvXDtTIegwRBtgMs
         Spzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) smtp.mailfrom=glaubitz@zedat.fu-berlin.de
Received: from outpost1.zedat.fu-berlin.de (outpost1.zedat.fu-berlin.de. [130.133.4.66])
        by gmr-mx.google.com with ESMTPS id e11-20020a05600c4e4b00b003db0d2c3d6esi83988wmq.0.2023.01.20.00.49.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Jan 2023 00:49:21 -0800 (PST)
Received-SPF: pass (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) client-ip=130.133.4.66;
Received: from inpost2.zedat.fu-berlin.de ([130.133.4.69])
          by outpost.zedat.fu-berlin.de (Exim 4.95)
          with esmtps (TLS1.3)
          tls TLS_AES_256_GCM_SHA384
          (envelope-from <glaubitz@zedat.fu-berlin.de>)
          id 1pIn53-002oea-Ri; Fri, 20 Jan 2023 09:49:01 +0100
Received: from p57bd9464.dip0.t-ipconnect.de ([87.189.148.100] helo=[192.168.178.81])
          by inpost2.zedat.fu-berlin.de (Exim 4.95)
          with esmtpsa (TLS1.3)
          tls TLS_AES_128_GCM_SHA256
          (envelope-from <glaubitz@physik.fu-berlin.de>)
          id 1pIn53-000p3c-GA; Fri, 20 Jan 2023 09:49:01 +0100
Message-ID: <c1d233b9-bc85-dce9-ffa0-eb3170602c6c@physik.fu-berlin.de>
Date: Fri, 20 Jan 2023 09:49:00 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.1
Subject: Re: Calculating array sizes in C - was: Re: Build
 regressions/improvements in v6.2-rc1
To: "Michael.Karcher" <Michael.Karcher@fu-berlin.de>,
 Geert Uytterhoeven <geert@linux-m68k.org>
Cc: linux-kernel@vger.kernel.org, amd-gfx@lists.freedesktop.org,
 linux-arm-kernel@lists.infradead.org, linux-media@vger.kernel.org,
 linux-wireless@vger.kernel.org, linux-mips@vger.kernel.org,
 linux-sh@vger.kernel.org, linux-f2fs-devel@lists.sourceforge.net,
 linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com,
 linux-xtensa@linux-xtensa.org,
 Michael Karcher <kernel@mkarcher.dialup.fu-berlin.de>,
 Arnd Bergmann <arnd@arndb.de>
References: <CAHk-=wgf929uGOVpiWALPyC7pv_9KbwB2EAvQ3C4woshZZ5zqQ@mail.gmail.com>
 <20221227082932.798359-1-geert@linux-m68k.org>
 <alpine.DEB.2.22.394.2212270933530.311423@ramsan.of.borg>
 <c05bee5d-0d69-289b-fe4b-98f4cd31a4f5@physik.fu-berlin.de>
 <CAMuHMdXNJveXHeS=g-aHbnxtyACxq1wCeaTg8LbpYqJTCqk86g@mail.gmail.com>
 <3800eaa8-a4da-b2f0-da31-6627176cb92e@physik.fu-berlin.de>
 <CAMuHMdWbBRkhecrqcir92TgZnffMe8ku2t7PcVLqA6e6F-j=iw@mail.gmail.com>
 <429140e0-72fe-c91c-53bc-124d33ab5ffa@physik.fu-berlin.de>
 <CAMuHMdWpHSsAB3WosyCVgS6+t4pU35Xfj3tjmdCDoyS2QkS7iw@mail.gmail.com>
 <0d238f02-4d78-6f14-1b1b-f53f0317a910@physik.fu-berlin.de>
 <1732342f-49fe-c20e-b877-bc0a340e1a50@fu-berlin.de>
Content-Language: en-US
From: John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>
In-Reply-To: <1732342f-49fe-c20e-b877-bc0a340e1a50@fu-berlin.de>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: 87.189.148.100
X-Original-Sender: glaubitz@physik.fu-berlin.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as
 permitted sender) smtp.mailfrom=glaubitz@zedat.fu-berlin.de
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

Hi Michael!

On 1/19/23 23:11, Michael.Karcher wrote:
> I suggest to file a bug against gcc complaining about a "spurious warning",
> and using "-Werror -Wno-error-sizeof-pointer-div" until gcc is adapted to
> not emit the warning about the pointer division if the result is not used.

Could you post a kernel patch for that? I would be happy to test it on my
SH-7785CLR board. Also, I'm going to file a bug report against GCC.

Adrian

-- 
  .''`.  John Paul Adrian Glaubitz
: :' :  Debian Developer
`. `'   Physicist
   `-    GPG: 62FF 8A75 84E0 2956 9546  0006 7426 3B37 F5B5 F913

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c1d233b9-bc85-dce9-ffa0-eb3170602c6c%40physik.fu-berlin.de.
