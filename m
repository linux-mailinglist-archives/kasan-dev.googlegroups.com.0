Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZEXXD5QKGQEVIFMWVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 110D3278C8B
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 17:25:25 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id b17sf1133911lji.10
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 08:25:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601047524; cv=pass;
        d=google.com; s=arc-20160816;
        b=UcDksj4S67ttZ91h6Mq6iRG+7L0OSBfV7gwLz1o3QwfpbeOgG1fSvAVRmic6mMtxWJ
         mgk2yyrEAvrV3BOpXnbuxNNSN6ftzKpuJwZZ8Dgz/7UKadOGKw3MsC9MjHZfR8qYg3al
         RWMidQf5Cq+1EB0+VWpdXbQUuUw6rpTb0WLmdwoyXyGKeV9KVQ08fwvwUF/PlmF9i1Ci
         ZA0cZYMEzeSFGTgVilncVNmQ9+rB4KocCPQQHN/hhG/pJOTLqjhlKpYrw32g+WOBgVGD
         dyzsJlMMtm2+aEzpJXKABOrw/Aq7kBBtkKh5o0LuvbK3zVWgbK7ufnlsRc3cLvtwOufR
         H79A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xP/oyiR8xld1d9kd14/yodiC7hcBwSJdJ31WQI2ubpw=;
        b=zsv8D44WhzJ1q/OBOw0pxM/uVj2wWi/0KvvDtmeznbeXf70FzTm783iNnwM10Zo9bs
         Yi+TJqhI+eCVySh0MWcIUJvbMcaWVyGTcd296q4m4JgnlCphsYctXd4hLJRFHOQTwFuG
         BZ+TFsNWlILfdIFwts28en98dwm3pWkUGXeXZpAhgElUBtm9SnAiVOtE8jfp2dBRUGH0
         F7pRDJ68wrh2qsTxXyo4KIXqPUq0U2b4uCduWy2QpTxkevVulrBVM3fVN9nJQDAVhxA5
         sEQ8HS1KtSsMu2SQy/6eOLWUETgdBcjUoQer9fDdNOCsOWa6tLKut/kekndkRlPUNzTh
         cClQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KM9OZ7Bi;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xP/oyiR8xld1d9kd14/yodiC7hcBwSJdJ31WQI2ubpw=;
        b=UEhJK0QfBSSL0MjtN+s+CprsvHWU9Ivi+zBJuY8b1KdN26NojjyVk9/79x4f5jBWkf
         P2Kc/09mFL4v23SqoO+Xy0vls+TCW/yOenxK4+L352B/JBtCC2QCeV3SKDMkTsFHe1ul
         6L3PjQFp2sLMbK1i7iCJ3NO7SF7fY/Gcb+RnfE08AoeM1cAkjrI3rMu/osF8fqfaU0Os
         52sjvf4//+9EyyB1tHVHJB6EA4cgx7NZmfpZFMiqNfITpNLKQ3m/HNEzr2PgjF3vQUIk
         owBRK4iw5EMc66qxF9G4ACskpcuQydR6b0fCOjrEHkSkjhy5ofcWMdNY7tLq25EPqhFe
         //1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xP/oyiR8xld1d9kd14/yodiC7hcBwSJdJ31WQI2ubpw=;
        b=R64rdx318t6dkC2/I2vu7vs86fr7l0v4BZ/8tSL5zrPGnHXhgVKuLuKHLjGXZU3sDa
         sqc/07DNONMgZNaFAa/gjOysCy9ZJ/qjWHbsEU2IzC5TTx8Y6WL130TSSLx3dV42MXk/
         bh8N+rlNZ3WYXTvW8I4lhOxS8wBYR/m1lNGTQ4NaFM926JCJNzC1QXKDdxCSBlKw7ss9
         DtuQTNGyMhs71ifFCB+7vJx40JKcEplen2SV49g5dZtAFywcgrErw7/In7b1PnuZgOZR
         cIXCx7Okcucx8RoFO+WuwCsP5gpjm3e6yFlZTk+vAj7b+BATljBANFnwngPsS8CsMzuc
         D9eA==
X-Gm-Message-State: AOAM533OsSbw2RW3dlOI+vp88sOYCndxHB7AsMW23++YaS8hJeCOJEMa
	pNqbKU3cgvuL8yDvuCPryG8=
X-Google-Smtp-Source: ABdhPJy36VRZH6+OipUgXEvJwv/YV+ZSE35o2CNF+WAuYDNjcodkqth0ZoJ1LCXtrKajeoTbjv++eQ==
X-Received: by 2002:a2e:898a:: with SMTP id c10mr1440195lji.4.1601047524606;
        Fri, 25 Sep 2020 08:25:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:93c7:: with SMTP id p7ls444762ljh.11.gmail; Fri, 25 Sep
 2020 08:25:23 -0700 (PDT)
X-Received: by 2002:a2e:a494:: with SMTP id h20mr1472200lji.116.1601047523589;
        Fri, 25 Sep 2020 08:25:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601047523; cv=none;
        d=google.com; s=arc-20160816;
        b=1DVa8hNJRaOBobOglSoYtB9Zgmmc5aLTMOYhE/WbAmgFOjL+7CkwN8Rq866ZTy5Mqx
         GwbR2vycMUIaRc+p6Ynnp3l2NpxHGqcmIW+DpWBGHs6NZ8UpQ4RUSaav3joIpnlMHMbQ
         jzN5YQd8YQUim5xM+AT1tVBT1edfoOwLdGcwYl9ZPajge/Wm1JPdTqQX/WKmvTXbUHTb
         CrLZu278LvRuTJxVFSjSd6p8/hMhTfpcJ8hGcMngUTR8Y8dm/DV6/XEKRvmX8phQAmC7
         fyCFx+prPR0et5vIOyT6xYsBJlwGVM3TJ3CsDjpAdsrT5Nf4ssjSSYiEfkuLLkg7veok
         yW6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=V7t4fEIEyVBsi/fjg9YkHb+gy/WAE7FgQtIkyl4FSCQ=;
        b=wA01J/EM1rfIfB36h38LVZoWuNthfnhqGmxx+kLBdATQzJ+Ruug7mCLWd1J11gp7QJ
         vHA8h6PykmV1rZZDVsfs5iVpDRBoc1TMOMaeqz0wRbuvedK+6FDcgXQzzpK2Ggh5GAHw
         njbj/KUufeQso/6rQe9fOHy+CdycjMHUPcsdda4LRYV2NAZ4ib4JYUOLRMCzxAaaPoZm
         sbVm77Fa9axRRfiOMkr9/p1181E5gh/lUl+U107vJanqtZjvgVoS2cp2A+f9A9uXSEXr
         5qw4r671kYK/AcSaYEaW3ath0vpTC7Mn5tmOXrsuy9qsM/13uGMa8mfpQY3/D08OsQn4
         GX0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KM9OZ7Bi;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id l82si59850lfd.13.2020.09.25.08.25.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Sep 2020 08:25:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id x14so3984347wrl.12
        for <kasan-dev@googlegroups.com>; Fri, 25 Sep 2020 08:25:23 -0700 (PDT)
X-Received: by 2002:a5d:4581:: with SMTP id p1mr5255102wrq.345.1601047522816;
 Fri, 25 Sep 2020 08:25:22 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-4-elver@google.com>
 <20200921143059.GO2139@willie-the-truck>
In-Reply-To: <20200921143059.GO2139@willie-the-truck>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 25 Sep 2020 17:25:11 +0200
Message-ID: <CAG_fn=WXknUnNmyniy_UE7daivSNmy0Da2KzNmX4wcmXC2Z_Mg@mail.gmail.com>
Subject: Re: [PATCH v3 03/10] arm64, kfence: enable KFENCE for ARM64
To: Will Deacon <will@kernel.org>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitriy Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, Jonathan.Cameron@huawei.com, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KM9OZ7Bi;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::444 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Will,

> Given that the pool is relatively small (i.e. when compared with our virtual
> address space), dedicating an area of virtual space sounds like it makes
> the most sense here. How early do you need it to be available?

How do we assign struct pages to a fixed virtual space area (I'm
currently experimenting with 0xffff7f0000000000-0xffff7f0000200000)?
Looks like filling page table entries (similarly to what's being done
in arch/arm64/mm/kasan_init.c) is not enough.
I thought maybe vmemmap_populate() would do the job, but it didn't
(virt_to_pfn() still returns invalid PFNs).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWXknUnNmyniy_UE7daivSNmy0Da2KzNmX4wcmXC2Z_Mg%40mail.gmail.com.
