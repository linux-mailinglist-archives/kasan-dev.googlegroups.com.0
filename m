Return-Path: <kasan-dev+bncBCT4XGV33UIBBXFB6OFAMGQEYDAM4KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id A62F8423372
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 00:25:34 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id s19-20020a63e813000000b00287d976d152sf407523pgh.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 15:25:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633472733; cv=pass;
        d=google.com; s=arc-20160816;
        b=g05l4j2qbqonJaQQoviAW/aSCtuGyGWR18NIMFvMyTUKELUue3dlA0Z7+5vDTGYZlD
         n3kO9zlJNmm9IBCrwb5DfqwX5L3DcIhf/cJhhKJ/IGolycGfh8kjOuYNNhwbsGx+5mh/
         pErEJ5lsHKUXbJt9H2wGkIPnBwk7rP4MJuXMbkdmtWA0GcbOdjoYfOTQU39H/qtPuNCq
         C4rNt0L1ZdFdvypKsCmKro+M46Bns9LPq9Uys/7jgbvFlrjYiKAj4721BT0BnkBtUOS6
         NU+EJOv+Rz25IJ0ReWa1c3sM4dlih/4HOqu2RMuyj3XQWx3rF4GGaqI0RF2a1GOPhrP3
         PY/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=BVqz7x6DMf4DeE/sfruVX1uxrxIvwgelFzy6O9+ZiL4=;
        b=Luf5Ep7p46NzML2leknNj/LCFJkI4afPrb/dSWnFmeP1B2SrOBkLRB+WB0whcmARYB
         RELfpirHCVjzRll8tCr4aKVWMev7gKnbBe6aADM4toL9lH2/jC6XHz/td34EeCcXZNI2
         oyzrSiZy8Stb417hcST1xy/Ahi9Y7h0xCazvSnhadKuU2M7EsRtEs+H/bM8lqbIgaAcL
         XJTbjQl9qzudVsEz8grTVdNgm31zXJAHSP22rMPNO8qitGsoZhckvS97/b9rGCRH3+hP
         km/+z/0vo1eoSXQIqN8Oh+DuOaDZkyKRAOCz0OwIEjTfH2H4RI2wTHyLMJbw4cwPpx4k
         SuUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=BfBcw3+Z;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BVqz7x6DMf4DeE/sfruVX1uxrxIvwgelFzy6O9+ZiL4=;
        b=FGU5+8PulMTRx/jUm45pnS9CWZOzc+ntnneEM0ur/6346HRMQSNMVpfSxNwIsSIifl
         r78/RLuagaqgKaHxLxTmxbR65i+GHUB3PJA+aKc3Opz8EyiqvPEsrNjcr4OS2oafI7t4
         JQdzDLUAp2xktK9mIfpBfUmBRohi0bvS4SkQg6dXLq4gMSloSu5AQdnmSlyaqRXbGH4u
         wtWGwAxBhjxkRaiT6o7XQEvZQad3rBsxAUscfCWJIR+Y91YghuIJfOFH1M7tJChhz9lx
         f3mzbFdc9RcdhpnnVFrKyTYop5s90WFL/9Em85ErkP3E7Y/vxqIiD/OoXRFICRYt/AiL
         1Jfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BVqz7x6DMf4DeE/sfruVX1uxrxIvwgelFzy6O9+ZiL4=;
        b=HtTMbPDNwX7M/dDABbbxsratPYVjHwF0QFivDifUHj3R2xNR6+NVjHuEoqk4zVCnHl
         oeaqLKNMkPalViKawCjDsgqtremNA6fwu31hTXHBJf7SbQtJ85r4oXUdMrhLWz/p+Qoo
         I2XchNZn2JdnbG338gyZ0NVP2gdf4bSfOUqzUO+BKKsFfBC6Ywayp15HikMauTRJX5JD
         Lr+65RvrlQOqi/Z5D5IKqTnpDHVDNp4l4cQpk2TZenq3FzOS1NRB4MPYNzm3/R6t41Z4
         4+6UdvouBfimv2pSFH5pOSbMQoeiPEy3rxLEpI/SSORouz276vz7G+tt1DAVFpY9qB93
         R8pg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5335DMQdI4x4cBjmOoPy00KOcVg9mrbBKRtKi8XNJV9K8yemZU+K
	NOLajZFiWc5Usmw2K3l/uvU=
X-Google-Smtp-Source: ABdhPJzIZSgqksy/dji/kkgHj/j1EHP45VL4UUHgAbsC9yT/mwV0z/ZldSCAH7VuDeaF1ZHoWn7CDw==
X-Received: by 2002:a63:4766:: with SMTP id w38mr5605069pgk.104.1633472732978;
        Tue, 05 Oct 2021 15:25:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3d45:: with SMTP id o5ls1914853pjf.1.canary-gmail;
 Tue, 05 Oct 2021 15:25:32 -0700 (PDT)
X-Received: by 2002:a17:90a:2:: with SMTP id 2mr6690378pja.77.1633472732386;
        Tue, 05 Oct 2021 15:25:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633472732; cv=none;
        d=google.com; s=arc-20160816;
        b=suCOEw6mzNvBKcBL9FsTabW4SZKOODhrvb4TJV+LBXP520AVToftFSP2BFX+d2Unev
         GeWUUyo2TfdC13e1AlWoLrUHrw1F6kAeDhtp9gLcGLc3sWtXcotgwyVrpfT6nOyNN6Gr
         zjksEJddY2sIc9Mh/bJbju1LvBbdYJtaOwR5qsqJqZ6DXXCt02sRsQbrcsQ1oS2x9qY7
         nSu0IEqlAQI4ADv/9CvNae8ILHHGJM47Shqb8oyIW9FKF0MN/TjHjdCiQ9bOPWNXBsNA
         A2TdbcttrN4cl9a6Rq3qwme8acOoXNpje69UnJlqTTHlqE8J6oOrFvpclz9478c9tBYu
         ZgZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Mdt2pgtWJcUTVNMfmThEtanXEApEt1CeHU/ndKrSJos=;
        b=o9O5OTvzV36gSZiZkJz6bhsnTuDMGUtYaFuuC9TyUO3rLn1r1yRegwCKbqHsgvCnkT
         e2E4g4GzOUdLXTCRbspaMuDI3es6a+Xk8WWRp0Df5ywljOmdFuZo3LkmXSy4Tb2Z67Nn
         HN4jJsKNK/1AjIZiQb/aUWGHIj3Seb/lFDKNDK/JBFiRFgg4sUuM4B/RFZAB2qFAMkUc
         U4/4OCZ3wwqwpv6BbNW+5FzcmSxyYZy6Ov64YVXkRt9gGhr87H+WuQty2NiLQ4aURQve
         bfrDqDZmI36FD7TwOfItkyfqsWAMdPVthIOQqfRc6Y/1lL3FbOMyrWd16AROfjuXSv4k
         puWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=BfBcw3+Z;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r7si339789pjp.0.2021.10.05.15.25.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 05 Oct 2021 15:25:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id AC2566108F;
	Tue,  5 Oct 2021 22:25:31 +0000 (UTC)
Date: Tue, 5 Oct 2021 15:25:31 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Catalin Marinas <catalin.marinas@arm.com>, Will
 Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, Andrey
 Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
 <glider@google.com>, Marco Elver <elver@google.com>, Evgenii Stepanov
 <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Lorenzo Pieralisi
 <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v2 0/5] arm64: ARMv8.7-A: MTE: Add asymm in-kernel
 support
Message-Id: <20211005152531.9b1443e659f4200cd4d7182d@linux-foundation.org>
In-Reply-To: <20211004202253.27857-1-vincenzo.frascino@arm.com>
References: <20211004202253.27857-1-vincenzo.frascino@arm.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=BfBcw3+Z;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon,  4 Oct 2021 21:22:48 +0100 Vincenzo Frascino <vincenzo.frascino@arm.com> wrote:

> This series implements the in-kernel asymmetric mode support for
> ARMv8.7-A Memory Tagging Extension (MTE), which is a debugging feature
> that allows to detect with the help of the architecture the C and C++
> programmatic memory errors like buffer overflow, use-after-free,
> use-after-return, etc.

I'm not sure which subsystem tree you were targeting here, so I grabbed
them.  I'll drop the -mm copy if this material pops up in a linux-next
via a different tree.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005152531.9b1443e659f4200cd4d7182d%40linux-foundation.org.
