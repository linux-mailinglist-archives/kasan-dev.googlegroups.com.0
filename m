Return-Path: <kasan-dev+bncBCT4XGV33UIBBJXCRPFAMGQEVPHHTJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D456CC930D
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 19:06:33 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-7b952a966d7sf12434162b3a.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 10:06:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765994791; cv=pass;
        d=google.com; s=arc-20240605;
        b=XkoVZrYnV5FgiufQHmjOL/hVtUkSkfv8pr+h0V3v1W0LHEMPYkv3dDJ3AUIWyKnsuR
         OPn42n/ZXsiD8R75NdKmbfcoM1rlsFHwyJCRRqr0B5VatFgQUjP3inPeFUmiSt3m+nyO
         KlDYU4e9bPdWIDyCYC0VYaH4Eg/vgXa7xuNjI9KAJRMV9Q0XI1QYGRGv4J/wsuFGRvAh
         cEjbVj7WxAXvAKkHbSCM7o1/pY9VW9n7GFu1g9dWCvSwt1y+yfeMeJh49IisAqY1cetB
         u5hUplJ/SILG7N/pbdGMRVD/DG0wwu5H2Pk/kDJj9jI4gsJ/lIaZblXjWo051KaD4xIR
         wYqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=B1llbnWce7vbN86hub55CQvpyQeSr3yYmBy1f1MfDic=;
        fh=qRzhAhTLypzzu2od7R9x85mgPlFftE8KAbafGLvCZ6g=;
        b=Iv3XIkrVrEcpIcbPdoJrHCcCP8OKprATqy9fr53xL2KqViPd1oEs00sqe6I5gFFD0M
         ufVdVlIuLYpmpIVEgTXTMXIZEHITUxtMKE4knTMM9UycWIxlRjbvcElf1sg11ihgc6jO
         XxGwY+DuL9iZbloGN7LYYo2BcfQxy/HKqBBvqkNs20CigLh1VBD65uH+C7EweIBImuUx
         D6C4PI47td2qWZ5R6xKxGti//lSlyoxFakzC6bsXTClHUyvACQ1B4EVXouxPNjClpeKN
         AsI17lfH3FbqbwdBBzjmGs2bS5Dsjgk2vXf3wBqU/6imUZVmT2SIa2513e62Fkgk7Xbu
         8t5Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=i1LOacvU;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765994791; x=1766599591; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=B1llbnWce7vbN86hub55CQvpyQeSr3yYmBy1f1MfDic=;
        b=vjBMgEVaqHBJ1Esbo2Gts545vGqLoLTYuYPmY+gGjXajjZJXJxmV1ZIt1/fJhzWp20
         WEWcW+vNUoNnnnzZNEm7qPw9sEv0yZl2IneAHNssROgwvmFbpLWmXQXPFGddbIDexlm2
         Skd8DWmWfkZdQtkueWr2ddrZrpXdhAzuqi4uEQz0MbMom63fQ8IsCksjZNIriShfAz0r
         SkQWg845uBkagFOkwjMwl3M/Ks6ByjPQ213fvCzI14goc/FaJfjaIAyKICuBOQoaNtR8
         EZhuoC8Or4AfLpD2oOhKbnFXzEgV219Ay37h91Dfz8hjRH0az0dqWHmHjLQFYKRY6szz
         Q1SA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765994791; x=1766599591;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=B1llbnWce7vbN86hub55CQvpyQeSr3yYmBy1f1MfDic=;
        b=fPpNZxuiM4DY0x5mAW9v5uSog6Et9F0YLOCfuIlcCXT7Vt5USr9HwY81yagmM6EmTw
         c4i1X6VCC7YmjNP+qc3j+kDqLqyOw66IqlfFtfLQDKkDBqq4hAuIXByBb8bfzzSWXimz
         /B/pPYjEyi7LLh+LUZ0d2T9w7ZNyo5DgsCbVSKPpZveJnujGgz5T1QY62JuIMrVxzOQw
         HXHWsrvcfJQeqY0K4CFq4CE4VmnJvBGPxwQLnJW9gjOA6ECAU5olhr0kcj9ids0UKtPc
         Zf58Mff6GGE5hL6DeEBwNG4pq+O2X6WyTiDyydz4/OQFkkBcHc+EaI+rfxLmnu8y6Jy8
         vPiA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUk8d9DsRnPhwOb7Irj9E4qZ1WxODy4TK84i5Utyt8Eus5+TliTst02+5uGAycu3VsqDKqrgw==@lfdr.de
X-Gm-Message-State: AOJu0YypFedaGbK3hTxcvUPPHKZLMab1sNhANpvXdu7FyKcEQvrKxSHX
	CNkA1mXqrfHR1gkFf5ZvYznlHK7y5TkesSdmVm04sfRXxcI3JoZrWkTM
X-Google-Smtp-Source: AGHT+IE8h1PeWdtG9B+YHAPpsVam6LQf14n8XO15WmANxQNnvR84uN2XCBDQCTZwBxMG3zWzRT/qLA==
X-Received: by 2002:a05:6a00:4108:b0:7f0:2d21:878e with SMTP id d2e1a72fcca58-7f66793631cmr17769923b3a.25.1765994791465;
        Wed, 17 Dec 2025 10:06:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZ2v8RwkkLIgin+gyydOwV+GNEqBKwZAlgTeQ66pFutag=="
Received: by 2002:a05:6a00:21d0:b0:7a6:a380:fc79 with SMTP id
 d2e1a72fcca58-7f648f423ecls7881314b3a.1.-pod-prod-06-us; Wed, 17 Dec 2025
 10:06:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXA9Z0chmLvqUuG0DnlnNpEXFucK3QAFS/s9X37vvr3vVn1UobyeDS41Tp+224VKZ5XFEp+1WpALys=@googlegroups.com
X-Received: by 2002:a05:6a21:6d9a:b0:366:14ac:e1d7 with SMTP id adf61e73a8af0-369affecf12mr21111962637.61.1765994789668;
        Wed, 17 Dec 2025 10:06:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765994789; cv=none;
        d=google.com; s=arc-20240605;
        b=OrZ+/r0/VOnKCGAaAKIYagSzKujzQm6o4ZxXBejax/tLlc/UHkUuN+HexP7CRBn86t
         7I3LjMBpfSZeaKT8zRUpt+XuUFV9ZjnfBXdz9DgxjXi5t3mS8QUreLJ+nofNsAcXT5Y5
         V3UYSuoW6iMfdTdz9PTMJLp3z5QRQzbH9kPWre8+Crs6FhZI84/BHx/ourL0Xf97Qi56
         nJ2gh09uHVuCtnRLf3/Jau4Tyt83RL/DC6SJJ5BCena1WxLXekXLEqPTxfn2V3RKuBSR
         jxzZ8Iz/BVqGGo8gnehDzJgiDQp3B+8AQEBKLvsBD2Tvz6HWpWNWf3SB7yJC+3zDtczd
         eMlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=uKo9H2d82owLfo6EnJra+LDY8Yr0eDCCzyDR7UhtiDI=;
        fh=n9RoppE8lnX/Xc5sb8tiUiQ+8uZTOZi7XCiJLnmweEg=;
        b=FGFltp5VWA7UM90vY9414jCmxqldFJJ4meJXNZV9pts0dfpEMrS6z91kumnPRXt5IE
         GvLVKArh0eLx+LN6FqX3cydvwKn6VFeo10BnmBuSnZk0iR9LJLODL77w9WQb2vGFjIik
         r1hB9CEkmvdrwKwfGpgu0UplXlsw5xjB6SSDLLRzcK8sUcTaQ/6H7nc+X+BCqU4wKJgZ
         MbLNfpHOfBrBon7zV9+x9WuxhqIxF0H82P5Af+7Bocs+vPfEv2ck1fkZTN2CIBKDBk++
         PzLvHpMyzSFNHJtLUY8hJFmsn/XOqxGXhAf1MKz64FB1hUeAF8jZMTVruXr+PbuXrzw0
         lJkQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=i1LOacvU;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-c1d2b14774dsi2571a12.0.2025.12.17.10.06.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Dec 2025 10:06:29 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 4EC86429F5;
	Wed, 17 Dec 2025 18:06:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B6B72C4CEF5;
	Wed, 17 Dec 2025 18:06:28 +0000 (UTC)
Date: Wed, 17 Dec 2025 10:06:28 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: urezki@gmail.com, kees@kernel.org, elver@google.com,
 andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com,
 ryabinin.a.a@gmail.com, dakr@kernel.org, glider@google.com,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
Subject: Re: [PATCH v5 0/3] kasan: vmalloc: Fixes for the percpu allocator
 and vrealloc
Message-Id: <20251217100628.ce0aef7cc975b81f0fc77cc8@linux-foundation.org>
In-Reply-To: <cover.1765978969.git.m.wieczorretman@pm.me>
References: <cover.1765978969.git.m.wieczorretman@pm.me>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=i1LOacvU;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 17 Dec 2025 13:48:44 +0000 Maciej Wieczor-Retman <m.wieczorretman@pm.me> wrote:

> Patches fix two issues related to KASAN and vmalloc.

Thanks for the refresh.  This is the same as we already have in
mm.git's mm-hotfixes-unstable branch.  So I updated the changelog
metadata a bit and left the v4 series in place.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251217100628.ce0aef7cc975b81f0fc77cc8%40linux-foundation.org.
