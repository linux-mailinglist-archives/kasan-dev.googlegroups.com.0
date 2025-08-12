Return-Path: <kasan-dev+bncBDW2JDUY5AORBXEB53CAMGQEWM4ZR3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 23A9FB230FA
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 19:58:54 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-3325d880267sf34520091fa.2
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 10:58:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755021533; cv=pass;
        d=google.com; s=arc-20240605;
        b=WqK3/Q7kPXfAI3DxNiExFclDR0x4dX6e5NSmIRgrolpkzrwBfqxJbZLn24oj3fb8Qi
         TQL6yBp6KY0nuVJa6HQetpckEgfj3g8p5WrpFrj+GaKPZ/LgWHQIlkjl0No8U+NjOiN0
         5Ojn/pieiLhN5/MPHC47jtkxdcWs9qphBh6fx00iW23Uh9fnThpR5AwE/Cd1Q+nxnzJD
         x8K2httON1/QvBVtpyDlQ93cxRL466GMA/YFn7mti8yluYW6vQlMMURKsa4cQQ4Bn62I
         cn9NIQBSzsGZGXtXO0Zu0oVFJ6HvaS95IjVPdPV4esCtU/fIz1SMrPymhuwxDNNtEid6
         nXTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=4PEOrlYB9Zqx9XDL5ty1rBn63XRwgV9Ltox3yuUbGaU=;
        fh=cSpOdvgceZWqWfvLJOWKXHuLKrTRPrmW/cdv/3mihBQ=;
        b=YSdCbPvjbGRxvv3V3y97ZR/zWmxrnH1trP7paTCW/b9MFnlFxqzIBdHZmUCoyRVdgA
         F2yJdkWKRcaVY6pAu36yGG78LfdFS96PZGQKLs6B3cbgmYE0PJhHCMQaympUNBzn/VTN
         1Z5GEmz3O57Y/mqsymkIlbkW07b1tn/RvTBilMxCXh2S6dT4n98lNBTsa5LVi8SuJUTA
         5buN6e/SkEOur5f88m4nJTiQHvFn8AtDJc2EhRDDTheGjNiRwewwQ8Yp/LAVZSu6koyK
         INHiJhFzFqKJGxkoBAr8dTvttCUDUlYmI+RfIuxf+f10bL/9FnjO5g9DIKRTrjoZC9bl
         dKKQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=P90wToDq;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755021533; x=1755626333; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4PEOrlYB9Zqx9XDL5ty1rBn63XRwgV9Ltox3yuUbGaU=;
        b=e1sN/EEWagYOa33ZE5J5Na2BbhxMIvRg/I3sprbN/hWVJ0BkOsT1bNHnSpE22OW10l
         ArWMY7HxInoc5s7GRdfq6KgGDwQ83XXYrzl0LbQOaBKH/5yWaGNZDlrShvkhY7olCWei
         Q+U+ViA7xOw5gKzHqQ+Fj3rCWi+Xc6mnC8Pf9JiEOQFrDOMlzGyYSuh08f7PZNhj4mds
         0nRWs5wpCE/f6MOsm9az8GdokFu02NBrvFFCyATndNXyorIlAlwKjzvhgjnwMazXbcc/
         8wkogk6LZieU8uBqfMSdS5uRHsSSTZ15noSp8MPZPaI794mqlFFDQdeXCV2LMPv6fKuV
         PuAg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755021533; x=1755626333; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4PEOrlYB9Zqx9XDL5ty1rBn63XRwgV9Ltox3yuUbGaU=;
        b=fyZ8PUC0ZM/pEK5XrCLav2p34QpcTIYe6fBKE+YdeFTcYp6WYzICzD45VDyoi+Wx//
         7r+IONWTS0x7Pe3IPm12Mq5Q1p4wWdZ0InYyL7litcHg5eProV1TVGJrnwnQNHZwNFRT
         GXaglY3k4TndQZCQfUCAlUlHnSXOwUjdXBy0lpYiro5VeilW6rmDGL8JNSzh7QtXFnfh
         haLl0lY4QlrWa395zfOSZ28ObqOttL6m1aoI6xnQFQCYuVol8+fzA85D7tuSMBP5oBbQ
         WYcwItoDWp3O8dG3YJheMidrqZd9xrcKN5obNoRl/ZtUMVdWtybZPafZBC/1ltDn7Bnw
         /OQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755021533; x=1755626333;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4PEOrlYB9Zqx9XDL5ty1rBn63XRwgV9Ltox3yuUbGaU=;
        b=rFtt/jPAmWh5y8GpAfkvg+ApD4g/S1iQ6KJt1DN8JWPCCcso7KGb0Lz+tyoV+/vALa
         kzmNAvtHKBPcaK7a0ml3QKxkEjrq0dkwMf93cK0f+G0bj1CkSmHZdV5nd35fCEdpQCIv
         NN0x+qXV2YjNICewx0wW3j22Xfixn51pWnQX3QKqSFL7xf9mmPIJbbUhUu41aUjmTLpQ
         6ID+8rKgs3Fy1E9fcExG3xycz/lbE181lnR9cxkzCAjCRgWVXYHy4Qm9bgvnRW5c4RCO
         TooiQTFFP3pPkVs0rPpFkodxCEirWzdFLjCfz8KkzR1c6AIjZbSaEEBRMHXoyAzEVHxn
         cuLg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUE57zfpRq+qXAlOR8R51uVjo1+Y/WGfQfgcHnLw5h3v7VZIJwLYn69OLdypkPn+TQaAQe6Iw==@lfdr.de
X-Gm-Message-State: AOJu0Yxf1s8fIDu5HEMvgwOXhKqCzhgAsGOy/oVPCOWA6zNQJLYp/rlu
	ZczzucvIdpLIKObuzV/VmsllIzxsHeaHMIQLkRfHQkDHy3XWUpYw+VLu
X-Google-Smtp-Source: AGHT+IEXuo57WmtfwDyKe7U3BmYBf2bzVeTlvDe8SMUgIbXx2erso20lsDjxtbqmn9GcjybtoQPlFg==
X-Received: by 2002:a05:651c:111a:b0:32b:9220:8020 with SMTP id 38308e7fff4ca-333e5410571mr1905701fa.34.1755021533210;
        Tue, 12 Aug 2025 10:58:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdlx3BHbFjCySBTD1M9Ss+IT36g0+wDUpi1rYQ4C/h+EA==
Received: by 2002:a19:5e5c:0:b0:556:27d9:6da8 with SMTP id 2adb3069b0e04-55cb5eaadd3ls1487764e87.0.-pod-prod-09-eu;
 Tue, 12 Aug 2025 10:58:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXe/ONPqerkNlNDCAWSkJWnrw6Izw9IEJw3OvcjE4ixj2hUE5usaXPYT5ghJlPMyrFxwdTUa9yKBuw=@googlegroups.com
X-Received: by 2002:a05:6512:a8b:b0:55b:9595:c7cd with SMTP id 2adb3069b0e04-55ce040b086mr55497e87.54.1755021530383;
        Tue, 12 Aug 2025 10:58:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755021530; cv=none;
        d=google.com; s=arc-20240605;
        b=el/M+6MWH5+/OIm4uYbWdOjDrqUn9P0fpA7JFuLO1f9CeIojJDNtuIhWIWEJMbzRVs
         1gAT7gbZK8acJR534D5NdFV+uToYCgBpcNI/wSUkTo/ImboLc/EZcEl+ekzRMCQX2vA7
         FEqTZn0AvXQIWvoiQslKAbtmpfa0wucwnXhhz1FXe9EJAFct+KXOtD3NPd4YhZX2bKJa
         sKyLF+Mw7C1mxDeEds8Fu1NjrpMxz9k0MsDDVfN36nsvtn4HVomR+H/Wi0ZvZe8Zik4G
         gV/uUNrvNg6etvq3mb9GNWSgqyYZyViYe/hWnSJ4ngq9lRsbKYLLm6E7rF9dH3lizLLj
         vR6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=qFgqOdxV1F9ejz004iGryJ3qWW5B6GXnUjljpVgqkLk=;
        fh=gZmSuydmXiqAHZEcNZ+LX0XFw36sQwlE7ssR35Qyx+U=;
        b=ijQj78TLLTt2KQfFfHRJe9AiBqQa0cDs/GoYn6Omy2hLXllxl+j0VDtByVE1m4Rbnd
         1d+0QWGoVnbfdcsWrHKFNzM55M5hvljq+qtZzBPzHl2xw0h2C0OSvOpG36ki0B+4yIWr
         DNXmChgmoN+Rz91TAvK8E0QrEccjk2ebytg3MbM5y9GkC47+w+gLHYDHGQadin8FoZ/z
         VmoQ7S5omW+7dxVFXfOF2UL8/e5ZXXMAuwe/9BjmayldDhUsHRlGIyBdVsGgxtxdD0s2
         WutX+3Qu8mL4YUymGnYiCqcUUuWRfCM5/vKr/wjodRRKwb0k5UJqPL5FgoERzx0gWPW3
         gwYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=P90wToDq;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b8895b6cbsi744630e87.7.2025.08.12.10.58.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Aug 2025 10:58:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-458bf6d69e4so52486895e9.2
        for <kasan-dev@googlegroups.com>; Tue, 12 Aug 2025 10:58:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUzdDiiKmjGGcI2ZIoJDUCSfI1oB35Q/T2v3k6WMkYAZJJdoSwgHACyR6V3rW/yd3YNgtCJpejd288=@googlegroups.com
X-Gm-Gg: ASbGncv6hHCKVOvRN21UuKWIqWr/jW5j0eNhDme4XQNgRWhHyBqsEtImGaMvrxoWlKO
	XcXwfrWTaBARZG70Ctmvv2/DfymIdv5H0KSDQeH+nu/WFsAgB0LNicP3ruUdD7xhS0Nr/PMB0vo
	48QGDMrZi3c1OK6F4F2l1YIGOo2O9/+o4QcsgDIdJofBwZej1dH6XEu85Tn1SJTaRqKa1j5rx0V
	EOhXBC7jg==
X-Received: by 2002:a05:600c:1c01:b0:458:bbed:a827 with SMTP id
 5b1f17b1804b1-45a165b7b15mr660355e9.1.1755021529570; Tue, 12 Aug 2025
 10:58:49 -0700 (PDT)
MIME-Version: 1.0
References: <20250811173626.1878783-1-yeoreum.yun@arm.com> <20250811173626.1878783-3-yeoreum.yun@arm.com>
 <CA+fCnZeSV4fDBQr-WPFA66OYxN8zOQ2g1RQMDW3Ok8FaE7=NXQ@mail.gmail.com> <aJtyR3hCW5fG+niV@e129823.arm.com>
In-Reply-To: <aJtyR3hCW5fG+niV@e129823.arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 12 Aug 2025 19:58:37 +0200
X-Gm-Features: Ac12FXy555KMqM9sRgAgjXOVEGNZdNcePtQ9D4aII7b1VUPGHKMWOpB_9plVIlw
Message-ID: <CA+fCnZeznLqoLsUOgB1a1TNpR9PxjZKrrVBhotpMh0KVwvzj_Q@mail.gmail.com>
Subject: Re: [PATCH 2/2] kasan: apply store-only mode in kasan kunit testcases
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, catalin.marinas@arm.com, 
	will@kernel.org, akpm@linux-foundation.org, scott@os.amperecomputing.com, 
	jhubbard@nvidia.com, pankaj.gupta@amd.com, leitao@debian.org, 
	kaleshsingh@google.com, maz@kernel.org, broonie@kernel.org, 
	oliver.upton@linux.dev, james.morse@arm.com, ardb@kernel.org, 
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com, 
	yang@os.amperecomputing.com, kasan-dev@googlegroups.com, 
	workflows@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=P90wToDq;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Aug 12, 2025 at 6:57=E2=80=AFPM Yeoreum Yun <yeoreum.yun@arm.com> w=
rote:
>
> > Right now, KASAN tests are crafted to avoid/self-contain harmful
> > memory corruptions that they do (e.g. make sure that OOB write
> > accesses land in in-object kmalloc training space, etc.). If you turn
> > read accesses in tests into write accesses, memory corruptions caused
> > by the earlier tests will crash the kernel or the latter tests.
>
> That's why I run the store-only test when this mode is "sync"
> In case of "async/asymm" as you mention since it reports "after",
> there will be memory corruption.
>
> But in case of sync, when the MTE fault happens, it doesn't
> write to memory so, I think it's fine.

Does it not? I thought MTE gets disabled and we return from the fault
handler and let the write instruction execute. But my memory on this
is foggy. And I don't have a setup right now to test.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeznLqoLsUOgB1a1TNpR9PxjZKrrVBhotpMh0KVwvzj_Q%40mail.gmail.com.
