Return-Path: <kasan-dev+bncBDDL3KWR4EBRBJ7OSD6QKGQE6FL3EEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id C0E172A84EC
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 18:32:24 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id t63sf1358969qke.10
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 09:32:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604597544; cv=pass;
        d=google.com; s=arc-20160816;
        b=a5N2NJVfbubRcQ547ThLeLn7X3vHYreAar/o06LUkIoypx49GsgOaByzHc0D0A+Jj1
         I2wOk6E6XCPDNUWA2ikVdGZPhOl5b4ZObwnzWpF5m7ZZUaDd+A79k2P9x42qOdu5ipML
         6q+6yaytg9RguIVDI8g8Z5qntbIAU0uxSdPt5R1Wq2o46T/7AFuVl/ee2VwDeiRzSGb7
         fv3TTZe1l4lY9BQImXDdeS5xiTKCHWk20xXNCLbLTzKOaihyzLynyb5WjD3H7JPJ9q1n
         YAv/DH3F4zo0UfjklerbCAe+5Shqf45DQwfg6xnTqWxaLjmacTOJfPY0Qm4xZ7tHOVtr
         Qd2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=nCz7YgzrmYJIHIfof870xKfQJyQQyQivNIfz2UHL66g=;
        b=CetXSDjSkWBrztpXYAr0GYlLJzZqQmTF7QCtYYVv94P9W0dOjgS2Gk9EOA0twdIYQq
         dBMfVsbMHmYrlk31B51g7hJc+y/0uErdVeqxdTIbyY9XkDFo6ktoZJJ4ZcdYDvh6WYig
         IFNrpSDCkpCjcqMtkNjZYtevsi+0F/mQ43w6VgsHLoLsoYoPzG5kVWHIFr/mpaZ1ydQy
         ym1z75Pgx1ZxMqE9072pCSXXOJJAYMRa6MXLHN2On8FDZlP1dt02iNCFcyGN1pWWpi9C
         2k6Kl8Eyhgn60mz1AAQAqoC7g3B3hw4goJk4xkd6KMcBB3ajRXlt1LCb9qbWmBcJ7i2K
         M21A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nCz7YgzrmYJIHIfof870xKfQJyQQyQivNIfz2UHL66g=;
        b=OdzgnpM+GRjNQGEWflhOcO8WNiuAEGhPJ16SGD4zHUAy0YNkwW32REiHW29TF93CbW
         mQZjutj44urWl0/m/0vYj9B5n+r5/SIYfSE3j0u0IzJWz9Q7i3tdCmhE3ShQ5MNvvYoS
         7sq17wsR0ITLtGJc6iYVW1Gj7PJCBrmszRA40Zkr2EnzAtGXDt45ouD/h22C6eDyh2xl
         oS95Pls4bMWXjFFmV+LlfErKPaECE1LOlrrmAKJyXfqCJoVkb7dtygRbUR/uAhY4v7tK
         jvxqR3DxtIBbGrZ+tK0Duoo7BSVTcmk6G1P+z3WWuCII9OCt2fswU1A6xEa4NunBro1b
         0jRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nCz7YgzrmYJIHIfof870xKfQJyQQyQivNIfz2UHL66g=;
        b=O0jZnGMSAlN3FVcPgSX0AMH7r7Uby41ZMoDEFJGMy1Wn2tmFwicF+NCKFrjWAXfoRn
         q+E8bfC48484tCCXuAPJfii2155YB9Q00bk50ZlyGvWhfDyT2KSY/uOnj5g/4mHIjAjQ
         a8wtrgsChn3ahRHRwj5/erK3Vr/kIAjZWEl9Fj4BXu9UZpCcjjB74EWv9LXIgZEfn6jr
         CvxRrduH/ApliFh6Je7Xv3Zs6noLIBkM1RLbQh/JTQSd0LCB/gl73qzAvSA0Oypl4QQb
         0Z95eLyqAoOi6Vjjcm7fvsgriAchMCEcqS0z5k0VDrF8us+U0EdwtVggxpUi4bW+L/Sl
         zbGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533MzzF9XuX6Ieja8WEqZeQ7Cyq3axVwH6pEEyuySO8nVK5O3pd/
	yRSswvNcTj/3Tc/or267sgA=
X-Google-Smtp-Source: ABdhPJwDPgMPdVAZDneeT7CjcjGfglfw5oIoaPwrEjwT0NsxEAB26U/FrjWEuve3td5ACXq5wJ4tkA==
X-Received: by 2002:ae9:dfc6:: with SMTP id t189mr3035670qkf.478.1604597543651;
        Thu, 05 Nov 2020 09:32:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4e29:: with SMTP id d9ls548784qtw.10.gmail; Thu, 05 Nov
 2020 09:32:23 -0800 (PST)
X-Received: by 2002:ac8:23dd:: with SMTP id r29mr2859278qtr.210.1604597542973;
        Thu, 05 Nov 2020 09:32:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604597542; cv=none;
        d=google.com; s=arc-20160816;
        b=kQe6FAKehZOsZMy7ubCPJYpMv1oR2IgyKW4cjM1l7Sr/QOrDDgjjhVI6AW/3XVXY7v
         Jah5Tfzt4QsY4mqIbOlHrOs2CZ7+xoBN597S7nM49VQkftXsgrSoO81zYaHJA50ArJvo
         IX9sQXrIKLmuc1IXjMyyKWo/S9gHQpBWmHs8HIDUGJ1Ub33WW+tS99g7OMvEQvh6CBaG
         pti9u5H08aWxAolf2OqFLbLKiUNU0WiWuBlfaDuCfWYTKPSPLnKPBVtpUTxgqb4cMgsQ
         RorsTSR0TUm9K1pNz9vwaHumW1g7Cvg+07SEQG3AMAc31oPz743JOvXJnBnQw6W4CFEe
         iIGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=YSnMSHhPCZ5M88cZJRiLprL1X1GB6pp/w/plBRj/Zy8=;
        b=f8k4/r/+/599zf5JUQhwVkrWi5WoUV+gMyPPiXUMkEAygJKS5JQRYuWrlNQhvdOSx7
         X1YRKqqBj1vi1ROQ4Bt6pT15fn+nK8E9JURc7CYr7hNc+mdYkm7Okr/dSfmXdztkEr7N
         Unix6DEpEfR17ntO1F2fjMx2K9mleLIuI+/TG2Hd1HmHrdObFamPtkXmbGWNoFeSfVeR
         MygEPlVaEe5Kplq28crlG8EnSCkXbPo8Mz/vMrDbttGB1IB+AQ//ip/UPezoA0KDr7GJ
         /HZ6EGZZts26ftSBzNOk/SPXa/PFyD21NYoUSDH0vAyZBEggbYa14kl9d66E2HXepyKd
         H40w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x11si150047qkn.0.2020.11.05.09.32.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Nov 2020 09:32:22 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 2F88E206CA;
	Thu,  5 Nov 2020 17:32:18 +0000 (UTC)
Date: Thu, 5 Nov 2020 17:32:15 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v8 37/43] kasan, arm64: expand CONFIG_KASAN checks
Message-ID: <20201105173214.GG30030@gaia>
References: <cover.1604531793.git.andreyknvl@google.com>
 <12faf1f7dc2d3f672f856e141dd9542e8a7cc7c1.1604531793.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <12faf1f7dc2d3f672f856e141dd9542e8a7cc7c1.1604531793.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Nov 05, 2020 at 12:18:52AM +0100, Andrey Konovalov wrote:
> Some #ifdef CONFIG_KASAN checks are only relevant for software KASAN
> modes (either related to shadow memory or compiler instrumentation).
> Expand those into CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201105173214.GG30030%40gaia.
